#!/usr/bin/python3

import logging
import os
import psycopg2
import time
import random


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
           


def main(logger):
    # TODO: Should do random wait from 0-300 seconds to ensure not all probe sites are on same five minute schedule

    minutesToSleep = 5
    secondsPerMinute = 60
    secondsToSleep = minutesToSleep * secondsPerMinute

    sleepPlusMinusVariation = 0.2

    sleepVariationSeconds = secondsToSleep * sleepPlusMinusVariation

    while True:
        serverList = _pullProbeList(logger)

        logger.info("Doing probes")


        thisSleepDurationSeconds = random.randint(
            secondsToSleep - sleepVariationSeconds, 
            secondsToSleep + sleepVariationSeconds)

        logger.info("Sleeping {0} seconds".format(thisSleepDurationSeconds))

        time.sleep( thisSleepDurationSeconds )




if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)
    main(logger)
