#!/usr/bin/python3

import logging
import os
import psycopg2
import random
import datetime
import pause
import ipaddress
import scapy.layers.inet
import scapy.layers.inet6
import scapy.layers.ntp
import scapy.sendrecv
import pprint
import influxdb


def _connectToDB(logger, dbDetails):
    return psycopg2.connect("dbname='{0}' user='{1}' host='{2}' password='{3}'".format(
        dbDetails['db_name'],
        dbDetails['db_user'],
        dbDetails['db_host'],
        dbDetails['db_passwd'])
    )


def _getDbCredentials(logger):

    dbDetails = {
        'db_host'       : os.environ['GLOBALPROBE_DB_HOST'],
        'db_user'       : os.environ['GLOBALPROBE_DB_USER'],
        'db_passwd'     : os.environ['GLOBALPROBE_DB_PASSWORD'],
        'db_name'       : os.environ['GLOBALPROBE_DB_NAME']
    }

    return dbDetails


def _pullProbeList(logger):
    dbCreds = _getDbCredentials(logger)

    addressesToProbe = []
    addressRows = None

    try:
        with _connectToDB(logger, dbCreds) as dbConnection:
            with dbConnection.cursor() as dbCursor:
                dbCursor.execute(
                    'SELECT owner_cognito_id, dns_name, address ' +
                    'FROM monitored_servers ' + 
                    'JOIN server_addresses ' +
                    'ON monitored_servers.server_id = server_addresses.server_id ' +
                    'ORDER BY dns_name, address;' )

                addressRows = dbCursor.fetchall()

    except Exception as e:
        logger.error("Hit exception when pulling server list, exception = {0}".format(e))

    for currentDbRow in addressRows:
        addressesToProbe.append(
            {
                'owner_id'          : currentDbRow[0],
                'dns_name'          : currentDbRow[1],
                'address'           : currentDbRow[2]
            }
        )

    logger.debug("Collected {0} addresses to probe".format(len(addressRows)) )

    #logger.debug(pprint.pformat(addressesToProbe))

    return addressesToProbe


def _getProbeTimeWindowSeconds(logger, windowSeconds, variationSeconds):

    return random.randint(
        windowSeconds - variationSeconds,
        windowSeconds + variationSeconds )


def _trimToMicroseconds(longFloat):
    return float( "{0:.6f}".format(longFloat) )


def _probeIp(logger, currIpAddress):

    # NTP offset of UNIX epoch taken from https://www.eecis.udel.edu/~mills/y2k.html
    ntpTimestampAtUnixEpoch = 2208988800

    ntpPort = 123

    generatedIpAddr = ipaddress.ip_address(currIpAddress)

    if generatedIpAddr.version == 4:
        ipLayer = scapy.layers.inet.IP(dst=currIpAddress)

    elif generatedIpAddr.version == 6:
        ipLayer = scapy.layers.inet6.IPv6(dst=currIpAddress)

    fullQuery = \
        ipLayer / \
        scapy.layers.inet.UDP(sport=random.randint(1024, 65535), dport=ntpPort) / \
        scapy.layers.ntp.NTP(version=3)

    #logger.info("Query: {0}".format(fullQuery[scapy.layers.ntp.NTP].show()))

    sentTime = datetime.datetime.utcnow()

    #logger.info("Sending query:\n{0}".format(fullQuery.summary()))
    serverReply = scapy.sendrecv.sr1(fullQuery, retry=3, timeout=3, verbose=False)

    # Did we even get a reply?
    if serverReply is None:
        return {
            'sent'      : sentTime,
            'timeout'   : datetime.datetime.utcnow()
        }

    # Get time response received
    responseReceivedTime = datetime.datetime.utcnow()

    # Convert current time to an NTP timestamp (seconds since 1900-01-01)
    responseReceivedNtpTimestamp = (responseReceivedTime - datetime.datetime.utcfromtimestamp(0)).total_seconds() + \
        ntpTimestampAtUnixEpoch


    responseNtp = serverReply[scapy.layers.ntp.NTP]
    #logger.info("Response:\n{0}".format(responseNtp.show()))

    replyTimes = {
        'ref'   : responseNtp.ref,
        'orig'  : responseNtp.orig,
        'recv'  : responseNtp.recv,
        'sent'  : responseNtp.sent
    }

    #logger.info("Response timestamps:\n{0}".format(pprint.pformat(replyTimes)))
    #logger.info("Computed received: {0}".format(responseReceivedNtpTimestamp))


    # Computing offset and delay.
    # Sources:
    #       https://www.meinbergglobal.com/english/info/ntp-packet.htm
    #       https://www.eecis.udel.edu/~mills/time.html

    t1 = replyTimes['orig']
    t2 = replyTimes['recv']
    t3 = replyTimes['sent']
    t4 = responseReceivedNtpTimestamp

    offset = _trimToMicroseconds( ((t2 - t1) + (t3 - t4)) / 2 )
    delay = _trimToMicroseconds( (t4 - t1) - (t3 - t2) )


    #logger.info("\nOffset: {0:9.6f}\n Delay: {1:9.6f}".format(offset, delay))

    returnData = {
        'request_sent'          : datetime.datetime.fromtimestamp(t1 - ntpTimestampAtUnixEpoch),
        'response_received'     : responseReceivedTime,
        'offset'                : offset,
        'delay'                 : delay,
        'ntp_packet_details': {
            'leap_indicator'        : responseNtp.leap,
            'protocol_version'      : responseNtp.version,
            'protocol_mode'         : responseNtp.mode,
            'server_stratum'        : responseNtp.stratum,
            'poll'                  : responseNtp.poll,
            'precision'             : responseNtp.precision,
            'root_delay'            : _trimToMicroseconds(responseNtp.delay),
            'root_dispersion'       : _trimToMicroseconds(responseNtp.dispersion),
            'timestamp_reference'   : responseNtp.ref,
            'timestamp_origin'      : responseNtp.orig,
            'timestamp_receive'     : responseNtp.recv,
            'timestamp_transmit'    : responseNtp.sent
        }
    }

    # Precision is a signed 8-bit value, so if it's > 127, make negative
    if returnData['ntp_packet_details']['precision'] > 127:
        returnData['ntp_packet_details']['precision'] = -(256 - returnData['ntp_packet_details']['precision'])

    if hasattr(responseNtp, 'id') is True:
        returnData['ntp_packet_details']['id'] = responseNtp.id
    if hasattr(responseNtp, 'ref_id') is True:
        returnData['ntp_packet_details']['ref_id'] = responseNtp.ref_id
        if returnData['ntp_packet_details']['ref_id'] is not None:
            returnData['ntp_packet_details']['ref_id'] = returnData['ntp_packet_details']['ref_id'].decode('utf-8')

    return returnData


def _fireProbes(logger, addressList, probeTimeoutSeconds):

    probeResults = {}

    for currAddressInfo in addressList:
        currIp              = currAddressInfo['address']
        currOwner           = currAddressInfo['owner_id']
        currHostname        = currAddressInfo['dns_name']

        logger.info("Sending probe to address {0} (owner={1}, hostname={2})".format(
            currIp, currOwner, currHostname) )

        responseStats = _probeIp(logger, currIp)
        if responseStats is not None:
            responseStats['dns_name'] = currHostname

            # logger.info(pprint.pformat(responseStats))
            probeResults[currIp] = responseStats

        #break

    #logger.info(pprint.pformat(probeResults))
    return probeResults



def _doSleep(logger, windowStartTime, probeEndTime, windowEndTime):

    if probeEndTime > windowEndTime:
        logger.error("Probe rounded ended AFTER five minute window!")
        logger.error("Window start: {0} UTC\n  Window end: {1} UTC\nProbes end: {2} UTC\n".format(
            windowStartTime, windowEndTime, probeEndTime) )
        raise Exception("Service probes exceeded five minute window")

    logger.info("Sleeping to window end time of {0} UTC ({1:.0f} seconds)".format(windowEndTime,
        (windowEndTime - probeEndTime).total_seconds()) )
    pause.until(windowEndTime)
    afterSleepTime = datetime.datetime.utcnow()
    logger.info("Awoke from sleep at {0} UTC".format(afterSleepTime) )



def _recordResultsInDatabase(logger, probeResults):

    #logger.info( "Going to log following:\n{0}".format(pprint.pformat(probeResults)) )

    influxClient = influxdb.InfluxDBClient(
        host        = os.environ['INFLUXDB_HOST'],
        port        = os.environ['INFLUXDB_PORT'],
        username    = os.environ['INFLUXDB_USER'],
        password    = os.environ['INFLUXDB_PASSWORD'],
        ssl         = True, 
        verify_ssl  = True )

    #dbList = influxClient.get_list_database()
    #logger.info("Databases:\n{0}".format(pprint.pformat(dbList)))

    influxClient.switch_database('globalprobe')

    logger.info("Connected to GlobalProbe Influx DB")

    influxMeasurementsToAdd = []

    for currAddress in probeResults:

        currResult = probeResults[currAddress]

        currMeasurement = {
            'measurement': 'ntp_query_response',
            'tags': {
                'ntp_server_dns_name'           : currResult['dns_name'],
                'ntp_server_address'            : currAddress,
                'probe_site'                    : os.environ['GLOBALPROBE_SITE_ID'],
                'ntp_id'                        : currResult['ntp_packet_details']['id'],
                'ntp_ref_id'                    : currResult['ntp_packet_details']['ref_id'],
            },
            'time': "{0}Z".format(currResult['response_received'].isoformat()),
            'fields': {
                'leap_indicator'        : currResult['ntp_packet_details']['leap_indicator'],
                'protocol_version'      : currResult['ntp_packet_details']['protocol_version'],
                'protocol_mode'         : currResult['ntp_packet_details']['protocol_mode'],
                'server_stratum'        : currResult['ntp_packet_details']['server_stratum'],
                'server_poll'           : currResult['ntp_packet_details']['poll'],
                'server_precision'      : currResult['ntp_packet_details']['precision'],
                'root_delay'            : currResult['ntp_packet_details']['root_delay'],
                'root_dispersion'       : currResult['ntp_packet_details']['root_dispersion'],
                'timestamp_reference'   : currResult['ntp_packet_details']['timestamp_reference'],
                'timestamp_origin'      : currResult['ntp_packet_details']['timestamp_origin'],
                'timestamp_receive'     : currResult['ntp_packet_details']['timestamp_receive'],
                'timestamp_transmit'    : currResult['ntp_packet_details']['timestamp_transmit'],
                'round_trip_time_secs'  : currResult['delay'],
                'utc_offset_secs'       : currResult['offset'],
            }
        }

        logger.info("Adding measurement to list:\n{0}".format(
            pprint.pformat(currMeasurement)) )

        influxMeasurementsToAdd.append(currMeasurement)
        
    influxClient.write_points(influxMeasurementsToAdd)





def main(logger):
    probeWindowMinutes = 2
    secondsPerMinute = 60
    secondsPerWindow = probeWindowMinutes * secondsPerMinute
    windowPlusMinusVariation = 0.2
    windowVariationSeconds = secondsPerWindow * windowPlusMinusVariation

    probeTimeoutSeconds = 10

    while True:
        serverList = _pullProbeList(logger)
        windowInSeconds = _getProbeTimeWindowSeconds(logger, secondsPerWindow, windowVariationSeconds)
        windowStartTime = datetime.datetime.utcnow()
        windowEndTime = windowStartTime + datetime.timedelta(seconds=windowInSeconds)
        logger.info("Probe window starting at {0} UTC, ending at {1} UTC ({2} seconds)".format(
            windowStartTime, windowEndTime, windowInSeconds) )
        probeResults = _fireProbes(logger, serverList, probeTimeoutSeconds)
        probeEndTime = datetime.datetime.utcnow()
        logger.info("Probe round ended at {0} UTC".format(probeEndTime) )

        _recordResultsInDatabase(logger, probeResults)

        #break

        _doSleep(logger, windowStartTime, probeEndTime, windowEndTime)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)
    main(logger)
