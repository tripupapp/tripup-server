package database

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/google/uuid"
	bolt "github.com/johnnadratowski/golang-neo4j-bolt-driver"

	"github.com/tripupapp/tripup-server/auth"
)

var debugLogger *log.Logger = log.New(os.Stdout, "[DEBUG] NeoLog: ", log.LstdFlags | log.Lshortfile)
var errLogger *log.Logger = log.New(os.Stderr, "[ERROR] NeoLog: ", log.LstdFlags | log.Lshortfile)

var neoDB *Neo4j
var once sync.Once

type Neo4j struct {
    driverPool bolt.DriverPool
}

func Instance() *Neo4j {
    once.Do(func() {
        neoDB = &Neo4j{}
    })
    return neoDB
}

func (neo *Neo4j) Connect() {
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

func (neo *Neo4j) CreateUser(id string, uuid string, authProviders auth.AuthProviders, publickey string, privatekey string, schemaVersion string) error {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "CREATE (user:User { uuid: {uuid}, publicKey: {publickey}, privateKey: {privatekey}, id: {id}, number: {number}, email: {email}, appleid: {appleid}, schemaVersion: {schemaVersion} }) " +
        "RETURN user.uuid")
    if err != nil {
        return err
    }
    defer stmt.Close() // closing the statment will also close the rows

    args := map[string]interface{} {
        "id": id,
        "uuid": uuid,
        "number": nil,
        "email": nil,
        "appleid": nil,
        "publickey": publickey,
        "privatekey": privatekey,
        "schemaVersion": schemaVersion,
    }

    if len(authProviders.PhoneNumber) != 0 {
        args["number"] = authProviders.PhoneNumber
    }
    if len(authProviders.Email) != 0 {
        args["email"] = authProviders.Email
    }
    if len(authProviders.AppleID) != 0 {
        args["appleid"] = authProviders.AppleID
    }

    // executing a statement just returns summary information
    result, err := stmt.ExecNeo(args)
    if err != nil {
        return err
    }

    _, err = result.RowsAffected()
    return err
}

func (neo *Neo4j) UpdateUserContact(id string, authProviders auth.AuthProviders) error {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return err
    }
    defer conn.Close()

    args := map[string]interface{} {
        "id": id,
        "number": nil,
        "email": nil,
        "appleid": nil,
    }

    var numberQuery string
    if len(authProviders.PhoneNumber) != 0 {
        args["number"] = authProviders.PhoneNumber
        numberQuery = "SET user.number = {number} "
    } else {
        numberQuery = "REMOVE user.number "
    }

    var emailQuery string
    if len(authProviders.Email) != 0 {
        args["email"] = authProviders.Email
        emailQuery = "SET user.email = {email} "
    } else {
        emailQuery = "REMOVE user.email "
    }

    var appleIDQuery string
    if len(authProviders.AppleID) != 0 {
        args["appleid"] = authProviders.AppleID
        appleIDQuery = "SET user.appleid = {appleid} "
    } else {
        appleIDQuery = "REMOVE user.appleid "
    }

    stmt, err := conn.PrepareNeo(
        "MATCH (user:User { id: {id} }) " +
        numberQuery +
        emailQuery +
        appleIDQuery)
    if err != nil {
        return err
    }
    defer stmt.Close() // closing the statment will also close the rows

    // executing a statement just returns summary information
    result, err := stmt.ExecNeo(args)
    if err != nil {
        return err
    }

    _, err = result.RowsAffected()
    return err
}

func (neo *Neo4j) GetUser(id string) (*map[string]string, error) {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return nil, err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (user:User { id: {id} }) " +
        "RETURN user.uuid, user.privateKey, user.schemaVersion")
    if err != nil {
        return nil, err
    }
    defer stmt.Close() // closing the statment will also close the rows

    args := map[string]interface{} {
        "id": id,
    }

    rows, err := stmt.QueryNeo(args)
    if err != nil {
        return nil, err
    }

    // query only returns 1 row, so will return io.EOF as error
    // second parameter is metadata, which is discarded
    data, _, err := rows.NextNeo()
    if err != nil && err != io.EOF {
        return nil, err
    }

    if len(data) == 0 { // no user found
        return nil, io.EOF
    }

    return &map[string]string {
        "uuid": data[0].(string),
        "privatekey": data[1].(string),
        "schemaVersion": data[2].(string),
    }, nil
}

func (neo *Neo4j) GetPublicInfoForUsers(uuids []string, numbers []string, emails []string) (map[string]string, map[string]map[string]string, error) {
    existingMatches := make(map[string]string)
    newMatches := make(map[string]map[string]string)

    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return existingMatches, newMatches, err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "WITH split({uuids}, ',') as uuids " + // notice the String split function - explanation below
        "MATCH (user:User) " +
        "WHERE user.uuid in uuids " +
        "RETURN user.uuid as id, true as uuid, user.publicKey " +
        "UNION " +
        "WITH split({numbers}, ',') as numbers " + // notice the String split function - explanation below
        "MATCH (user:User) " +
        "WHERE user.number in numbers " +
        "RETURN user.number as id, user.uuid as uuid, user.publicKey " +
        "UNION " +
        "WITH split({emails}, ',') as emails " + // notice the String split function - explanation below
        "MATCH (user:User) " +
        "WHERE user.email in emails " +
        "RETURN user.email as id, user.uuid as uuid, user.publicKey " +
        "UNION " +
        "WITH split({emails}, ',') as emails " + // notice the String split function - explanation below
        "MATCH (user:User) " +
        "WHERE user.appleid in emails " +
        "RETURN user.appleid as id, user.uuid as uuid, user.publicKey")
    if err != nil {
        return existingMatches, newMatches, err
    }
    defer stmt.Close() // closing the statment will also close the rows

    // transform uuids array to a comma seperated string
    // we do this because variable substitution using the golang neo4j driver does not work with arrays
    // see: https://github.com/johnnadratowski/golang-neo4j-bolt-driver/pull/8 which is currently unmerged
    // so we must substitute as a string, then in cypher, split string back to array
    uuidsString := fmt.Sprintf("%v", strings.Join(uuids, ","))
    numbersString := fmt.Sprintf("%v", strings.Join(numbers, ","))
    emailsString := fmt.Sprintf("%v", strings.Join(emails, ","))

    args := map[string]interface{} {
        "uuids": uuidsString,
        "numbers": numbersString,
        "emails": emailsString,
    }

    rows, err := stmt.QueryNeo(args)
    if err != nil {
        return existingMatches, newMatches, err
    }

    // foundUUIDS is a Golang Set, used to prevent duplicate uuids from being returned to client
    type void struct{}
    var member void
    foundUUIDS := make(map[string]void)
    for row, _, err := rows.NextNeo(); err != io.EOF; row, _, err = rows.NextNeo() {
        if err != nil {
            return existingMatches, newMatches, err
        }

        switch uuid := row[1].(type) {
        case bool:
            actualUUID := row[0].(string)
            existingMatches[actualUUID] = row[2].(string)
        case string:
            if _, exists := foundUUIDS[uuid]; exists {
                continue
            }
            newMatches[row[0].(string)] = map[string]string {
                "uuid": uuid,
                "publicKey": row[2].(string),
            }
            foundUUIDS[uuid] = member
        default:
            return existingMatches, newMatches, errors.New("unknown type in field")
        }
    }

    if len(existingMatches) == 0 && len(newMatches) == 0 {
        return existingMatches, newMatches, io.EOF
    }
    return existingMatches, newMatches, nil
}

func (neo *Neo4j) VerifyUUIDS(uuids []string) ([]string, error) {
    if len(uuids) == 0 {
        errLogger.Panicln()
    }

    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        errLogger.Panicln(err)
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "WITH split({uuidstring}, ',') as uuids " + // notice the String split function - explanation below
        "MATCH (user:User) " +
        "WHERE user.uuid in uuids " +
        "RETURN user.uuid")
    if err != nil {
        errLogger.Panicln(err)
    }
    defer stmt.Close() // closing the statment will also close the rows

    // transform uuids array to a comma seperated string
    // we do this because variable substitution using the golang neo4j driver does not work with arrays
    // see: https://github.com/johnnadratowski/golang-neo4j-bolt-driver/pull/8 which is currently unmerged
    // so we must substitute as a string, then in cypher, split string back to array
    uuidstring := fmt.Sprintf("%v", strings.Join(uuids, ","))

    args := map[string]interface{} {
        "uuidstring": uuidstring,
    }

    rows, err := stmt.QueryNeo(args)
    if err != nil {
        errLogger.Panicln(err)
    }

    var result []string
    for {
        row, _, err := rows.NextNeo()
        if err == nil {
            result = append(result, row[0].(string))
        } else if err == io.EOF {
            break
        } else {
            errLogger.Panicln(err)
        }
    }

    if len(result) == 0 {
        return nil, io.EOF
    }

    return result, nil
}

func (neo *Neo4j) GetGroups(id string) (map[string]map[string]interface{}, error) {
    data := make(map[string]map[string]interface{})

    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return data, err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (user:User {id: {id} }) - [membership:MEMBER] - (group:Group) " +
        "OPTIONAL MATCH (group) - [:MEMBER] - (users:User) " +
        "WHERE user <> users " +
        "RETURN group.uuid, group.name, membership.key, CASE WHEN users IS NOT NULL THEN collect({uuid: users.uuid, key: users.publicKey}) ELSE [] END")
    if err != nil {
        return data, err
    }
    defer stmt.Close() // closing the statment will also close the rows

    args := map[string]interface{} {
        "id": id,
    }
    rows, err := stmt.QueryNeo(args)
    if err != nil {
        return data, err
    }

    for row, _, err := rows.NextNeo(); err != io.EOF; row, _, err = rows.NextNeo() {
        if err != nil {
            return data, err
        }
        data[row[0].(string)] = map[string]interface{} {
            "name": row[1].(string),
            "key": row[2].(string),
            "members": row[3].([]interface{}),
        }
    }

    if len(data) == 0 {
        return data, io.EOF
    }
    return data, nil
}

func (neo *Neo4j) CreateAsset(id string, assetid string, assettype string, remotepath string, createdate *string, location *string, duration *string, originalfilename *string, originaluti *string, pixelwidth int, pixelheight int, md5 string, key string, remotepathorig *string, totalsize *uint64) error {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return err
    }
    defer conn.Close()

    fields := "memory.key = {key}, asset.type = {type}, asset.remotepath = {remotepath}, asset.remotepathorig = {remotepathorig}, asset.createdate = {createdate}, asset.location = {location}, asset.duration = {duration}, asset.originalfilename = {originalfilename}, asset.originaluti = {originaluti}, asset.pixelwidth = {pixelwidth}, asset.pixelheight = {pixelheight}, asset.md5 = {md5}, asset.totalsize = {totalsize} "

    stmt, err := conn.PrepareNeo(
        "MATCH (user:User { id: {id} }) " +
        "MERGE (user) <- [memory:MEMORY] - (asset:Asset { uuid: {assetid} }) " +
        "ON CREATE SET " + fields +
        "ON MATCH SET " + fields)
    if err != nil {
        return err
    }
    defer stmt.Close() // closing the statment will also close the rows

    // executing a statement just returns summary information
    input := map[string]interface{} {
        "id": id,
        "assetid": assetid,
        "type": assettype,
        "remotepath": remotepath,
        "remotepathorig": nil,
        "createdate": nil,
        "location": nil,
        "duration": nil,
        "originalfilename": nil,
        "originaluti": nil,
        "md5": md5,
        "pixelwidth": pixelwidth,
        "pixelheight": pixelheight,
        "key": key,
        "totalsize": nil }
    if createdate != nil {
        input["createdate"] = *createdate
    }
    if location != nil {
        input["location"] = *location
    }
    if duration != nil {
        input["duration"] = *duration
    }
    if originalfilename != nil {
        input["originalfilename"] = *originalfilename
    }
    if originaluti != nil {
        input["originaluti"] = *originaluti
    }
    if remotepathorig != nil {
        input["remotepathorig"] = *remotepathorig
    }
    if totalsize != nil {
        input["totalsize"] = *totalsize
    }

    result, err := stmt.ExecNeo(input)
    if err != nil {
        return err
    }

    _, err = result.RowsAffected()
    return err
}

func (neo *Neo4j) AddPathForOriginalAsset(id string, assetid string, remotepathorig string, totalsize uint64) error {
    if totalsize <= 0 {
        return errors.New("totalsize invalid")
    }

    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        errLogger.Panicln(err)
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (:User { id: {id} }) <- [:MEMORY] - (asset:Asset { uuid: {assetid} }) " +
        "SET asset.remotepathorig = {remotepathorig}, asset.totalsize = {totalsize} ")
    if err != nil {
        errLogger.Panicln(err)
    }
    defer stmt.Close() // closing the statment will also close the rows

    // executing a statement just returns summary information
    result, err := stmt.ExecNeo(map[string] interface{} {
        "id": id,
        "assetid": assetid,
        "remotepathorig": remotepathorig,
        "totalsize": totalsize,
    })
    if err != nil {
        errLogger.Panicln(err)
    }

    _, err = result.RowsAffected()
    if err != nil {
        errLogger.Panicln(err)
    }

    return err
}

func (neo *Neo4j) SetAssetOriginalFilename(id string, assetid string, originalfilename string) error {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (:User { id: {id} }) <- [:MEMORY] - (asset:Asset { uuid: {assetid} }) " +
        "SET asset.originalfilename = {originalfilename} ")
    if err != nil {
        return err
    }
    defer stmt.Close() // closing the statment will also close the rows

    // executing a statement just returns summary information
    result, err := stmt.ExecNeo(map[string] interface{} {
        "id": id,
        "assetid": assetid,
        "originalfilename": originalfilename,
    })
    if err != nil {
        return err
    }

    _, err = result.RowsAffected()
    return err
}

func (neo *Neo4j) LeaveGroup(ownerid string, groupid string) error {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (user:User { id: {ownerid} }) - [membership:MEMBER] - (group:Group { uuid: {groupid} }) " +
        "SET group._lock = true " +
        "DELETE membership " +
        "WITH user, group " +
        "OPTIONAL MATCH (group) - [invites:MEMBER {inviter: user.uuid}] - (:User) " +
        "DELETE invites " +
        "WITH user, group " +
        "OPTIONAL MATCH (group) - [groupRel:GROUP_ASSET] - (assets:Asset) - [:MEMORY] - (user) " +
        "DELETE groupRel " +
        "WITH group, assets " +
        "OPTIONAL MATCH (assets) - [sharedmemories:MEMORY_SHARED] - (users:User) " +
        "WHERE NOT (users) - [:MEMBER] - (:Group) - [:GROUP_ASSET] - (assets) " +
        "DELETE sharedmemories " +
        "WITH group " +
        "WHERE size((group) - [] - ()) = 0 " +
        "DELETE group ")
    if err != nil {
        return err
    }
    defer stmt.Close() // closing the statment will also close the rows

    // executing a statement just returns summary information
    result, err := stmt.ExecNeo(map[string] interface{} {
        "ownerid": ownerid,
        "groupid": groupid })
    if err != nil {
        return err
    }

    _, err = result.RowsAffected()
    return err
}

func (neo *Neo4j) DeleteAssets(userid string, assetids []string) (*[]string, error) {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return nil, err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (user:User { id: {userid} }) " +
        "WITH user, split({assetids}, ',') as assetids " + // notice the String split function - explanation below
        // remove references for assets that aren't owned by user
        "OPTIONAL MATCH (user) - [memoryShared:MEMORY_SHARED] - (assets:Asset) " +
        "WHERE assets.uuid in assetids " +
        "DELETE memoryShared " +
        // delete assets completely for assets that are owned by user
        "WITH user, assetids " +
        "MATCH (user) - [:MEMORY] - (assets:Asset) " +
        "WHERE assets.uuid in assetids " +
        "WITH assets, assets.remotepath AS remotepaths, assets.remotepathorig AS remotepathsoriginal " +
        "DETACH DELETE assets " +
        "RETURN remotepaths, remotepathsoriginal ")
    if err != nil {
        return nil, err
    }
    defer stmt.Close() // closing the statment will also close the rows

    // transform assetids array to a comma seperated string
    // we do this because variable substitution using the golang neo4j driver does not work with arrays
    // see: https://github.com/johnnadratowski/golang-neo4j-bolt-driver/pull/8 which is currently unmerged
    // so we must substitute as a string, then in cypher, split string back to array
    assetidsstring := fmt.Sprintf("%v", strings.Join(assetids, ","))

    rows, err := stmt.QueryNeo(map[string] interface{} {
        "userid": userid,
        "assetids": assetidsstring,
    })
    if err != nil {
        return nil, err
    }

    var pathsToDelete []string
    for row, _, err := rows.NextNeo(); err != io.EOF; row, _, err = rows.NextNeo() {
        if err != nil {
            return &pathsToDelete, err
        }
        pathsToDelete = append(pathsToDelete, row[0].(string))
        pathsToDelete = append(pathsToDelete, row[1].(string))
    }

    return &pathsToDelete, nil
}

func (neo *Neo4j) RemoveAssetsFromGroup(userid string, groupid string, assetids []string) error {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (user:User { id: {userid} }) - [:MEMBER] - (group:Group { uuid: {groupid} }) " +
        "SET group._lock = true " +
        "WITH user, group, split({assetids}, ',') as assetids " +    // notice the String split function - explanation below
        "MATCH (user) - [:MEMORY] - (assets:Asset) - [groupassets:GROUP_ASSET] - (group) " +
        "WHERE assets.uuid in assetids " +
        "DELETE groupassets " +
        "WITH assets " +
        "MATCH (assets) - [sharedmemories:MEMORY_SHARED] - (users:User) " +
        "WHERE NOT (users) - [:MEMBER] - (:Group) - [:GROUP_ASSET] - (assets) " +
        "DELETE sharedmemories ")
    if err != nil {
        return err
    }
    defer stmt.Close() // closing the statment will also close the rows

    // transform assetids array to a comma seperated string
    // we do this because variable substitution using the golang neo4j driver does not work with arrays
    // see: https://github.com/johnnadratowski/golang-neo4j-bolt-driver/pull/8 which is currently unmerged
    // so we must substitute as a string, then in cypher, split string back to array
    assetidsstring := fmt.Sprintf("%v", strings.Join(assetids, ","))
    input := map[string]interface{} {
        "userid": userid,
        "groupid": groupid,
        "assetids": assetidsstring,
    }

    // executing a statement just returns summary information
    result, err := stmt.ExecNeo(input)
    if err != nil {
        return err
    }

    _, err = result.RowsAffected()
    return err
}

func (neo *Neo4j) AddAssetsToGroup(userid string, groupid string, assetids []string) error {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (user:User { id: {userid} }) - [:MEMBER] - (group:Group { uuid: {groupid} }) " +
        "SET group._lock = true " +
        "WITH user, group, split({assetids}, ',') as assetids " +    // notice the String split function - explanation below
        "MATCH (user) - [:MEMORY] - (assets:Asset) " +
        "WHERE assets.uuid in assetids " +
        "MERGE (assets) - [:GROUP_ASSET] -> (group) ")
    if err != nil {
        return err
    }
    defer stmt.Close() // closing the statment will also close the rows

    // transform assetids array to a comma seperated string
    // we do this because variable substitution using the golang neo4j driver does not work with arrays
    // see: https://github.com/johnnadratowski/golang-neo4j-bolt-driver/pull/8 which is currently unmerged
    // so we must substitute as a string, then in cypher, split string back to array
    assetidsstring := fmt.Sprintf("%v", strings.Join(assetids, ","))
    input := map[string]interface{} {
        "userid": userid,
        "groupid": groupid,
        "assetids": assetidsstring,
    }

    // executing a statement just returns summary information
    result, err := stmt.ExecNeo(input)
    if err != nil {
        return err
    }

    _, err = result.RowsAffected()
    return err
}

func (neo *Neo4j) ShareAssets(id string, groupid string, assetids []string, assetkeys []string) error {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (user:User { id: {id} }) - [:MEMBER] -> (group:Group { uuid: {groupid} }) <- [groupasset:GROUP_ASSET] - (asset:Asset { uuid: {assetid} }) - [:MEMORY] -> (user) " +
        "SET group._lock = true, groupasset.sharedKey = {key} " +
        "WITH user, group, asset " +
        "MATCH (group) - [:MEMBER] - (others:User) " +
        "WHERE user <> others " +
        "MERGE (asset) - [:MEMORY_SHARED] -> (others) ")
    if err != nil {
        return err
    }
    defer stmt.Close() // closing the statment will also close the rows

    // have to use loop as the unofficial neo4j go driver cannot encode lists/maps
    for index, assetid := range assetids {
        result, err := stmt.ExecNeo(map[string] interface{} {   // executing a statement just returns summary information
            "id": id,
            "groupid": groupid,
            "assetid": assetid,
            "key": assetkeys[index] })
        if err != nil {
            return err
        }
        _, err = result.RowsAffected(); if err != nil {
            return err
        }
    }
    return err
}

func (neo *Neo4j) UnshareAssets(id string, groupid string, assetids []string) error {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "WITH split({assetids}, ',') as assetids " +    // notice the String split function - explanation below
        "MATCH (user:User { id: {id} }) - [:MEMBER] - (group:Group { uuid: {groupid} }) - [groupassets:GROUP_ASSET] - (assets:Asset) - [:MEMORY] - (user) " +
        "WHERE assets.uuid in assetids " +
        "SET group._lock = true " +
        "REMOVE groupassets.sharedKey " +
        "WITH assets " +
        "MATCH (assets) - [sharedmemories:MEMORY_SHARED] - (:User) " +
        "DELETE sharedmemories ")
    if err != nil {
        return err
    }
    defer stmt.Close() // closing the statment will also close the rows

    // transform assetids array to a comma seperated string
    // we do this because variable substitution using the golang neo4j driver does not work with arrays
    // see: https://github.com/johnnadratowski/golang-neo4j-bolt-driver/pull/8 which is currently unmerged
    // so we must substitute as a string, then in cypher, split string back to array
    assetidsstring := fmt.Sprintf("%v", strings.Join(assetids, ","))

    // executing a statement just returns summary information
    result, err := stmt.ExecNeo(map[string] interface{} {
        "id": id,
        "groupid": groupid,
        "assetids": assetidsstring})
    if err != nil {
        return err
    }

    _, err = result.RowsAffected()
    return err
}

func (neo *Neo4j) SetFavourite(userid string, tripid string, assetid string) {
    // safety checks
    if len(userid) == 0 || len(tripid) == 0 || len(assetid) == 0 {
        errLogger.Panicln()
    }

    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        errLogger.Panicln(err)
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (:User { id: {userid} }) <- [:TRIP_OWNER] - (:Trip { uuid: {tripid} }) <- [memory] - (:Asset { uuid: {assetid} }) " +
        "SET memory.favourite = TRUE ")
    if err != nil {
        errLogger.Panicln(err)
    }
    defer stmt.Close() // closing the statment will also close the rows

    // executing a statement just returns summary information
    result, err := stmt.ExecNeo(map[string] interface{} {
        "userid": userid,
        "tripid": tripid,
        "assetid": assetid })
    if err != nil {
        errLogger.Panicln(err)
    }

    _, err = result.RowsAffected()
    if err != nil {
        errLogger.Panicln(err)
    }
}

func (neo *Neo4j) UnsetFavourite(userid string, tripid string, assetid string) {
    // safety checks
    if len(userid) == 0 || len(tripid) == 0 || len(assetid) == 0 {
        errLogger.Panicln()
    }

    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        errLogger.Panicln(err)
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (:User { id: {userid} }) <- [:TRIP_OWNER] - (:Trip { uuid: {tripid} }) <- [memory] - (:Asset { uuid: {assetid} }) " +
        "REMOVE memory.favourite")
    if err != nil {
        errLogger.Panicln(err)
    }
    defer stmt.Close() // closing the statment will also close the rows

    // executing a statement just returns summary information
    result, err := stmt.ExecNeo(map[string] interface{} {
        "userid": userid,
        "tripid": tripid,
        "assetid": assetid })
    if err != nil {
        errLogger.Panicln(err)
    }

    _, err = result.RowsAffected()
    if err != nil {
        errLogger.Panicln(err)
    }
}

func (neo *Neo4j) PatchSchema0(id string, assetkeys map[string]string, assetmd5s map[string]string) error {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return err
    }
    defer conn.Close()

    replaceKeyStatement, err := conn.PrepareNeo(
        "MATCH (:User { id: {id} }) <- [memory:MEMORY] - (:Asset {uuid: {assetid} }) " +
        "SET memory.key = {key} " +
        "REMOVE memory.legacy_tripKey, memory.legacy_assetKey ")
    if err != nil {
        return err
    }
    defer replaceKeyStatement.Close() // closing the statment will also close the rows

    // have to use loop as the unofficial neo4j go driver cannot encode lists/maps
    for assetid, key := range assetkeys {
        result, err := replaceKeyStatement.ExecNeo(map[string] interface{} {   // executing a statement just returns summary information
            "id": id,
            "assetid": assetid,
            "key": key })
        if err != nil {
            return err
        }
        _, err = result.RowsAffected(); if err != nil {
            return err
        }
    }
    replaceKeyStatement.Close()

    setMD5Statement, err := conn.PrepareNeo(
        "MATCH (:User { id: {id} }) <- [memory:MEMORY|:MEMORY_SHARED] - (asset:Asset {uuid: {assetid} }) " +
        "SET asset.md5 = {md5} ")
    if err != nil {
        return err
    }
    defer setMD5Statement.Close() // closing the statment will also close the rows

    // have to use loop as the unofficial neo4j go driver cannot encode lists/maps
    for assetid, md5 := range assetmd5s {
        result, err := setMD5Statement.ExecNeo(map[string] interface{} {   // executing a statement just returns summary information
            "id": id,
            "assetid": assetid,
            "md5": md5 })
        if err != nil {
            return err
        }
        _, err = result.RowsAffected(); if err != nil {
            return err
        }
    }
    setMD5Statement.Close()

    // finally, set schema version for user
    setSchemaStatement, err := conn.PrepareNeo(
        "MATCH (user:User { id: {id} }) " +
        "SET user.schemaVersion = '1' ")
    if err != nil {
        return err
    }
    defer setSchemaStatement.Close() // closing the statment will also close the rows

    result, err := setSchemaStatement.ExecNeo(map[string] interface{} {   // executing a statement just returns summary information
        "id": id })
    if err != nil {
        return err
    }
    _, err = result.RowsAffected()
    return err
}

func (neo *Neo4j) GetAssets(id string) ([]interface{}, error) {
    query :=
        "MATCH (user:User {id: {id} }) - [memory:MEMORY] - (asset:Asset) " +
        "WITH user.uuid as ownerid, (asset), memory.key as key, exists(memory.favourite) as favourite " +
        "RETURN asset{.*, ownerid, key, favourite} as assets " +
        "UNION " +
        "MATCH (user:User {id: {id} }) - [memory:MEMORY_SHARED] - (asset:Asset) - [groupasset:GROUP_ASSET] - (group:Group) - [:MEMBER] - (user) " +
        "MATCH (asset:Asset) - [:MEMORY] - (owner:User) " +
        "WITH owner.uuid as ownerid, (asset), groupasset.sharedKey as key, exists(memory.favourite) as favourite, group.uuid as groupid " +
        "RETURN DISTINCT asset{.*, ownerid, key, favourite, groupid} as assets "
    return neo.getAssets(id, query)
}

func (neo *Neo4j) GetAssetsSchema0(id string) ([]interface{}, error) {
    query :=
        "MATCH (user:User {id: {id} }) - [memory:MEMORY] - (asset:Asset) " +
        "RETURN {id: asset.uuid, remotepathorig: asset.remotepathorig, tripkey: memory.legacy_tripKey, assetkey: memory.legacy_assetKey, key: memory.key, md5: asset.md5} as assets " +
        "UNION " +
        "MATCH (user:User {id: {id} }) - [memory:MEMORY_SHARED] - (asset:Asset) - [groupasset:GROUP_ASSET] - (group:Group) - [:MEMBER] - (user) " +
        "RETURN {id: asset.uuid, remotepathorig: asset.remotepathorig, groupid: group.uuid, sharedkey: groupasset.sharedKey, md5: asset.md5} as assets "
    return neo.getAssets(id, query)
}

func (neo *Neo4j) getAssets(id string, query string) ([]interface{}, error) {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return nil, err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(query)
    if err != nil {
        return nil, err
    }
    defer stmt.Close() // closing the statment will also close the rows

    args := map[string]interface{} {
        "id": id,
    }

    rows, err := stmt.QueryNeo(args)
    if err != nil {
        return nil, err
    }

    var data []interface{}
    err = nil
    for row, _, err := rows.NextNeo(); err != io.EOF; row, _, err = rows.NextNeo() {
        if err != nil {
            return nil, err
        }
        data = append(data, row[0])
    }
    if len(data) == 0 {
        return nil, io.EOF
    }
    return data, nil
}

func (neo *Neo4j) GetAssetsForAllGroups(userid string) (map[string]map[string][]interface{}, error) {
    data := make(map[string]map[string][]interface{})

    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return data, err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (user:User {id: {userid} }) - [:MEMBER] - (group:Group) " +
        "WITH user, group " +
        "OPTIONAL MATCH (user) - [:MEMORY|:MEMORY_SHARED] - (assets:Asset) - [:GROUP_ASSET] - (group) " +
        "WITH user, group, CASE WHEN assets IS NOT NULL THEN collect(assets.uuid) ELSE [] END as assetids " +
        "OPTIONAL MATCH (user) - [:MEMORY|:MEMORY_SHARED] - (assets:Asset) - [groupassets:GROUP_ASSET] - (group) " +
        "WHERE exists(groupassets.sharedKey) " +
        "RETURN group.uuid, assetids, CASE WHEN assets IS NOT NULL THEN collect(assets.uuid) ELSE [] END as sharedassetids ")
    if err != nil {
        return data, err
    }
    defer stmt.Close() // closing the statment will also close the rows

    args := map[string]interface{} {
        "userid": userid,
    }
    rows, err := stmt.QueryNeo(args)
    if err != nil {
        return data, err
    }

    for row, _, err := rows.NextNeo(); err != io.EOF; row, _, err = rows.NextNeo() {
        if err != nil {
            return data, err
        }
        data[row[0].(string)] = map[string][]interface{} {
            "assetids": row[1].([]interface{}),
            "sharedassetids": row[2].([]interface{}),
        }
    }

    if len(data) == 0 {
        return data, io.EOF
    }
    return data, nil
}

func (neo *Neo4j) GetUsersInGroup(id string, groupID string) (map[string]string, error) {
    data := make(map[string]string)

    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return data, err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (:User { id: {id} }) - [:MEMBER] -> (:Group { uuid: {groupID} }) <- [:MEMBER] - (otheruser:User) " +
        "RETURN otheruser.uuid, otheruser.publicKey ")
    if err != nil {
        return data, err
    }
    defer stmt.Close() // closing the statment will also close the rows

    args := map[string]interface{} {
        "id": id,
        "groupID": groupID,
    }

    rows, err := stmt.QueryNeo(args)
    if err != nil {
        return data, err
    }

    for row, _, err := rows.NextNeo(); err != io.EOF; row, _, err = rows.NextNeo() {
        if err != nil {
            return data, err
        }
        data[row[0].(string)] = row[1].(string)
    }

    if len(data) == 0 {
        return data, io.EOF
    }
    return data, nil
}

func (neo *Neo4j) CreateGroup(id string, groupid string, name string, key string) error {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (user:User { id: {id} }) " +
        "MERGE (user) - [:MEMBER {key: {key} }] -> (:Group { uuid: {groupid}, name: {name} })")
    if err != nil {
        return err
    }
    defer stmt.Close() // closing the statment will also close the rows

    // executing a statement just returns summary information
    result, err := stmt.ExecNeo(map[string] interface{} {
        "id": id,
        "groupid": groupid,
        "name": name,
        "key": key })
    if err != nil {
        return err
    }

    _, err = result.RowsAffected()
    return err
}

func (neo *Neo4j) JoinGroup(id string, groupID string, groupKey string) error {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (user:User { id: {id} }) - [membership:MEMBER] - (group:Group { uuid: {groupID} }) " +
        "SET group._lock = true " +
        "SET membership.key = {groupKey} " +
        "REMOVE membership.inviter " +
        "WITH user, group " +
        "MATCH (group) - [groupasset:GROUP_ASSET] - (assets:Asset) " +
        "WHERE exists(groupasset.sharedKey) " +
        "MERGE (user) <- [:MEMORY_SHARED] - (assets) ")
    if err != nil {
        return err
    }
    defer stmt.Close() // closing the statment will also close the rows

    // executing a statement just returns summary information
    result, err := stmt.ExecNeo(map[string] interface{} {
        "id": id,
        "groupID": groupID,
        "groupKey": groupKey })
    if err != nil {
        return err
    }
    _, err = result.RowsAffected()
    return err
}

func (neo *Neo4j) AddUsersToGroup(id string, groupid string, users []map[string]string) error {
    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        return err
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (primaryUser:User {id: {id} }) - [:MEMBER] - (group:Group {uuid: {groupid} }) " +
        "SET group._lock = true " +
        "WITH primaryUser, group " +
        "MATCH (user:User {uuid: {userid} }) " +
        "MERGE (user) - [:MEMBER { key: {membershipkey}, inviter: primaryUser.uuid }] -> (group) ")
    if err != nil {
        return err
    }
    defer stmt.Close() // closing the statment will also close the rows

    // have to use loop as the unofficial neo4j go driver cannot encode lists/maps
    for _, user := range users {
        result, err := stmt.ExecNeo(map[string] interface{} {   // executing a statement just returns summary information
            "id": id,
            "groupid": groupid,
            "userid": user["uuid"],
            "membershipkey": user["key"] })
        if err != nil {
            return err
        }
        _, err = result.RowsAffected(); if err != nil {
            return err
        }
    }
    return err
}

func (neo *Neo4j) UserIsMemberOfGroup(groupid string, user *uuid.UUID) (bool, error) {
    // safety checks
    if len(groupid) == 0 {
        errLogger.Panicln("failed safety check")
    }

    conn, err := neo.driverPool.OpenPool()
    if err != nil {
        errLogger.Panicln(err)
    }
    defer conn.Close()

    stmt, err := conn.PrepareNeo(
        "MATCH (:User { uuid: {uuid} }) - [r:MEMBER] -> (:Group { uuid: {guuid} })" +
        "RETURN SIGN(COUNT(r))")
    if err != nil {
        errLogger.Panicln(err)
    }
    defer stmt.Close() // closing the statment will also close the rows

    args := map[string]interface{} {
        "uuid": user.String(),
        "guuid": groupid,
    }

    rows, err := stmt.QueryNeo(args)
    if err != nil {
        errLogger.Panicln(err)
    }

    // query only returns 1 row, so will return io.EOF as error
    // second parameter is metadata, which is discarded
    data, _, err := rows.NextNeo()
    if err != nil && err != io.EOF {
        errLogger.Panicln(err)
    }

    if len(data) == 0 {
        return false, io.EOF
    }

    result := data[0].(int64)

    if result == 1 {
        return true, nil
    }

    return false, nil
}
