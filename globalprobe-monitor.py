#!/usr/bin/python3

import logging
import os
import psycopg2
import time
import random
import datetime
import pause


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

    


def _fireProbes(logger, addressList, probeTimeoutSeconds):

    for currAddress in addressList:
         
        pass 

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

        _doSleep(logger, windowStartTime, probeEndTime, windowEndTime)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)
    main(logger)
