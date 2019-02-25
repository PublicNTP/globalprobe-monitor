#!/usr/bin/python3

import logging
import os
import psycopg2
import random
import datetime
import pause
import ipaddress
import scapy.layers.inet
import scapy.layers.ntp
import scapy.sendrecv
import pprint


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
                    'SELECT owner_cognito_id, dns_name, server_address_id, address ' +
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
                'server_address'    : currentDbRow[2],
                'address'           : currentDbRow[3]
            }
        )

    logger.debug("Collected {0} addresses to probe".format(len(addressRows)) )

    #logger.debug(pprint.pformat(addressesToProbe))

    return addressesToProbe


def _getProbeTimeWindowSeconds(logger, windowSeconds, variationSeconds):

    return random.randint(
        windowSeconds - variationSeconds,
        windowSeconds + variationSeconds )


def _probeIp(logger, currIpAddress):

    # NTP offset of UNIX epoch taken from https://www.eecis.udel.edu/~mills/y2k.html
    # ntpTimestampAtUnixEpoch = 2208988800

    # Python from https://stackoverflow.com/questions/39466780/simple-sntp-python-script
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = '\x1b' + 47 * '\0'
    client.sendto(data.encode('utf-8'), (currIpAddress, 123))
    data, address = client.recvfrom(1024)
    if data: 
        print('Response received from {0}:'.format(address))
        t = struct.unpack('!12I', data)[10] - TIME1970
        print('\tTime = {0}'.format(time.ctime(t)) )
    """

    ntpPort = 123

    generatedIpAddr = ipaddress.ip_address(currIpAddress)

    if generatedIpAddr.version == 4:
        ipLayer = scapy.layers.inet.IP(dst=currIpAddress)

    elif generatedIpAddr.version == 6:
        logger.warn("Bailing on ipv6")
        return
        ipLayer = scapy.layers.inet.IPv6(dst=currIpAddress)

    fullQuery = ipLayer / scapy.layers.inet.UDP(dport=ntpPort) / scapy.layers.ntp.NTP(version=4)

    #logger.info("Query: {0}".format(fullQuery[scapy.layers.ntp.NTP].show()))

    #logger.info("Sending query:\n{0}".format(fullQuery.summary()))
    serverReply = scapy.sendrecv.sr1(fullQuery, retry=5, timeout=10, verbose=False)

    # Get time response received
    responseReceivedTime = datetime.datetime.utcnow()

    # Convert current time to an NTP timestamp (seconds since 1900-01-01)
    ntpTimestampAtUnixEpoch = 2208988800
    responseReceivedNtpTimestamp = (responseReceivedTime - datetime.datetime.utcfromtimestamp(0)).total_seconds() + \
        ntpTimestampAtUnixEpoch


    # Scapy NTP doesn't appear to be able to decode, which is unfortunate 
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

    offset = ( (t2 - t1) + (t3 - t4) ) / 2
    delay = (t4 - t1) - (t3 - t2)

    #logger.info("\nOffset: {0:9.6f}\n Delay: {1:9.6f}".format(offset, delay))

    return {
        'sent'      : datetime.datetime.fromtimestamp(t1 - ntpTimestampAtUnixEpoch),
        'offset'    : offset,
        'delay'     : delay
    }


def _fireProbes(logger, addressList, probeTimeoutSeconds):

    probeResults = {}

    for currAddressInfo in addressList:
        currIp              = currAddressInfo['address']
        currOwner           = currAddressInfo['owner_id']
        currHostname        = currAddressInfo['dns_name']
        currServerAddress   = currAddressInfo['server_address']

        logger.info("Sending probe to address {0} (owner={1}, hostname={2})".format(
            currIp, currOwner, currHostname) )

        responseStats = _probeIp(logger, currIp)
        if responseStats is not None:
            responseStats['server_address'] = currServerAddress

            # logger.info(pprint.pformat(responseStats))
            probeResults[currIp] = responseStats

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

    try:
        with _connectToDB(logger,  _getDbCredentials(logger)) as dbConnection:
            with dbConnection.cursor() as dbCursor:
                dataRows = []

                siteIdString = os.environ['GLOBALPROBE_SITE_ID']

                dbCursor.execute( 
                    "SELECT probe_site_id " +
                    "FROM probe_sites " + 
                    "WHERE site_location_id = %s;",

                    (siteIdString,) )

                result = dbCursor.fetchone()
                globalProbeSiteId = result[0]

                logger.info("Global probe site ID for {0}: {1}".format(siteIdString, globalProbeSiteId))


                for currIp in probeResults:

                    currResult = probeResults[currIp]

                    if abs(currResult['delay']) > 100 or abs(currResult['offset']) > 100:
                        logger.warn("Got invalid results in probe {0}, skipping".format(
                            pprint.pformat(currResult)) )
                        continue
                    else:

                        #logger.info("Curr result: {0}".format(pprint.pformat(currResult)))
                    
                        newDataRow = (
                            globalProbeSiteId,
                            currResult['server_address'],
                            currResult['sent'].isoformat(),
                            (currResult['sent'] + datetime.timedelta(seconds=currResult['delay'])).isoformat(),
                            "{0:.9f} seconds".format(currResult['delay']),
                            "{0:.9f} seconds".format(currResult['offset'])
                        )

                        #logger.info("Tuple to add to list:\n{0}".format(pprint.pformat(newDataRow)))

                        dataRows.append(newDataRow)

                """
                for currRow in dataRows:
                    logger.debug("Here's mogrify: {0}".format(
                        dbCursor.mogrify("(%s,%s,%s,%s,%s,%s)", currRow).decode("utf-8"))
                    )
                """

                args_str = ','.join(dbCursor.mogrify("(%s,%s,%s,%s,%s,%s)", x).decode("utf-8") for x in dataRows)

                #logger.debug(args_str)

                dbCursor.execute(
                    "INSERT INTO service_probes (probe_site_id, server_address, time_request_sent, " +
                        "time_response_received, round_trip_time, estimated_utc_offset )" +
                    "VALUES " + args_str)
                dbConnection.commit()



    except Exception as e:
        logger.error("Hit exception when adding probe history, exception = {0}".format(e))

    
    


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

        _doSleep(logger, windowStartTime, probeEndTime, windowEndTime)
        #break


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)
    main(logger)
