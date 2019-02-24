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
                'owner_id'  : currentDbRow[0],
                'dns_name'  : currentDbRow[1],
                'address'   : currentDbRow[2]
            }
        )

    logger.info("Collected {0} addresses to probe".format(len(addressRows)) )

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
    serverReply = scapy.sendrecv.sr1(fullQuery)

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


    # Computing offset and delay, per https://www.meinbergglobal.com/english/info/ntp-packet.htm
    t1 = replyTimes['orig']
    t2 = replyTimes['recv']
    t3 = replyTimes['sent']
    t4 = responseReceivedNtpTimestamp

    offset = ( (t2 - t1) + (t3 - t4) ) / 2
    delay = (t4 - t1) - (t3 - t2)

    logger.info("\nOffset: {0:9.6f}\n Delay: {1:9.6f}".format(offset, delay))













def _fireProbes(logger, addressList, probeTimeoutSeconds):

    for currAddressInfo in addressList:
        currIp          = currAddressInfo['address']
        currOwner       = currAddressInfo['owner_id']
        currHostname    = currAddressInfo['dns_name']

        logger.info("Sending probe to address {0} (owner={1}, hostname={2})".format(
            currIp, currOwner, currHostname) )

        _probeIp(logger, currIp)

        #break
         


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
    


def main(logger):
    # TODO: Should do random wait from 0-300 seconds to ensure not all probe sites are on same five minute schedule

    minutesToSleep = 5
    secondsPerMinute = 60
    secondsToSleep = minutesToSleep * secondsPerMinute
    sleepPlusMinusVariation = 0.2
    sleepVariationSeconds = secondsToSleep * sleepPlusMinusVariation

    probeTimeoutSeconds = 10

    while True:
        serverList = _pullProbeList(logger)
        windowInSeconds = _getProbeTimeWindowSeconds(logger, secondsToSleep, sleepVariationSeconds)
        windowStartTime = datetime.datetime.utcnow()
        windowEndTime = windowStartTime + datetime.timedelta(seconds=windowInSeconds)
        logger.info("Probe window starting at {0} UTC, ending at {1} UTC ({2} seconds)".format(
            windowStartTime, windowEndTime, windowInSeconds) )
        _fireProbes(logger, serverList, probeTimeoutSeconds)
        probeEndTime = datetime.datetime.utcnow()
        logger.info("Probe round ended at {0} UTC".format(probeEndTime) )

        #_doSleep(logger, windowStartTime, probeEndTime, windowEndTime)
        break


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)
    main(logger)
