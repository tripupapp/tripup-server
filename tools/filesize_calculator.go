package main

import (
	"fmt"
	"io"
	"log"
	"os"

	bolt "github.com/johnnadratowski/golang-neo4j-bolt-driver"
	"github.com/tripupapp/tripup-server/storage"
)

var errLogger = log.New(os.Stderr, "[ERROR] ServerLog: ", log.LstdFlags | log.Lshortfile)

type neo4j struct {
    driverPool bolt.DriverPool
}

func (neo *neo4j) connect() {
    user, exists := os.LookupEnv("TRIPUP_NEO_USER")
    if !exists {
        errLogger.Panicln("TRIPUP_NEO_USER not set")
    }
    pass, exists := os.LookupEnv("TRIPUP_NEO_PASS")
    if !exists {
        errLogger.Panicln("TRIPUP_NEO_PASS not set")
    }
    host, exists := os.LookupEnv("TRIPUP_NEO_HOST")
    if !exists {
        errLogger.Panicln("TRIPUP_NEO_HOST not set")
    }
    port, exists := os.LookupEnv("TRIPUP_NEO_PORT")
    if !exists {
        errLogger.Panicln("TRIPUP_NEO_PORT not set")
    }

    driverpool, err := bolt.NewDriverPool(
        fmt.Sprintf("bolt://%s:%s@%s:%s", user, pass, host, port),
        10) // max 10 connections - need to increase later!!!!
    if err != nil {
        errLogger.Panicln("error creating driverpool")
    } else {
        neo.driverPool = driverpool
    }
}

func main() {
    // initialise
    var storageBackend = storage.NewS3Backend()
    var neo4j = neo4j{}
    neo4j.connect()

    // prepare neo4j query for image remote paths
    conn1, err := neo4j.driverPool.OpenPool()
    if err != nil {
        errLogger.Panicln(err.Error())
    }
    defer conn1.Close()
    query, err := conn1.PrepareNeo(
        "MATCH (asset:Image) " +
        "WHERE NOT asset.remotepathorig IS NULL " +
        "RETURN asset.remotepathorig ")
    if err != nil {
        errLogger.Panicln(err.Error())
    }
    defer query.Close()

    // prepare statement for writing filesizes to neo4j
    conn2, err := neo4j.driverPool.OpenPool()
    if err != nil {
        errLogger.Panicln(err.Error())
    }
    defer conn2.Close()
    stmt, err := conn2.PrepareNeo(
        "MATCH (asset:Image { remotepathorig: {remotepathorig} }) " +
        "SET asset.totalsize = {totalsize} ")
    if err != nil {
        errLogger.Panicln(err.Error())
    }
    defer stmt.Close()

    // execute query
    rows, err := query.QueryNeo(nil)
    if err != nil {
        errLogger.Panicln(err.Error())
    }
    for row, _, err := rows.NextNeo(); err != io.EOF; row, _, err = rows.NextNeo() {
        // for each row, calculate filesizes, then write back to neo4j
        if err != nil {
            errLogger.Panicln(err.Error())
        }
        var remotePathOrig = row[0].(string)
        originalLength, lowLength, err := storageBackend.Filesizes(remotePathOrig)
        if err != nil {
            errLogger.Println(remotePathOrig)
            errLogger.Panicln(err.Error())
        }

        result, err := stmt.ExecNeo(map[string] interface{} {   // executing a statement just returns summary information
            "remotepathorig": remotePathOrig,
            "totalsize": originalLength + lowLength,
        })
        if err != nil {
            errLogger.Panicln(err.Error())
        }
        _, err = result.RowsAffected(); if err != nil {
            errLogger.Panicln(err.Error())
        }
    }
}
