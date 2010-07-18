########################################################
# CJGB, 20100628
########################################################

# Loads the required python packages and creates a 
#   connection to GS

gs.connect <- function( access.key = NULL, secret.access.key = NULL ){

    foo <- function(){
        assign(".gsutil", rJython( modules = list( system.file( "python", package = "rGSutil" ) ) ), .GlobalEnv)
        .gsutil$exec("from gsutil import *")
    }

    foo()

    has.goog.creds <- jython.call( .gsutil, "SetupConfigIfNeeded" )

    if( has.goog.creds )
        invisible( NULL )

    if( is.null( access.key ) | is.null( secret.access.key ) ) {
        rm( .gsutil, envir = .GlobalEnv )
        stop( "Missing credentials for Google Storage. Please, provide them as arguments." )
    }

    jython.call( .gsutil, "CreateBotoConfigFile", access_key = access.key, secret_access_key = secret.access.key )
    
    rm( .gsutil, envir = .GlobalEnv )
    foo()

    invisible( NULL )
}



# Implements ls command on GS storage

gs.ls <- function( files = "gs://", verbose = 0, show = TRUE ){

    if( !exists( ".gsutil" ) )
        stop( "You need to connect to GS using function gs.connect first" )

    tmp <- jython.call( .gsutil, "ListCommand", args = as.list( files ), verbose = verbose )
    if( show ) print( tmp )
    invisible( tmp )

}



# Implements mb (make bucket) command on GS storage

gs.mb <- function( files = "gs://" ){
    if( !exists( ".gsutil" ) )
        stop( "You need to connect to GS using function gs.connect first" )

    jython.call( .gsutil, "MakeBucketsCommand", args = as.list( files ) )
    invisible( NULL )
}



# Implements rb (remove bucket) command on GS storage

gs.rb <- function( files = NULL ){
    if( !exists( ".gsutil" ) )
        stop( "You need to connect to GS using function gs.connect first" )

    if( !is.null( files ) )
        jython.call( .gsutil, "RemoveBucketsCommand", args = as.list( files ) )
    invisible( NULL )
}



# Implements rm (remove object) command on GS storage

gs.rm <- function( files = NULL ){
    if( !exists( ".gsutil" ) )
        stop( "You need to connect to GS using function gs.connect first" )

    if( !is.null( files ) )
        jython.call( .gsutil, "RemoveObjsCommand", args = as.list( files ) )
    invisible( NULL )
}



# Implements cp (copy) command on GS storage

gs.cp <- function( fromUri, destUri, setMimeType = FALSE, cannedAcl = NULL ){

    if( !exists( ".gsutil" ) )
        stop( "You need to connect to GS using function gs.connect first" )

    if( !is.list( fromUri ) ) fromUri <- as.list( fromUri )
    #if( !is.list( destUri ) ) destUri <- as.list( destUri )

    jython.call( .gsutil, "CopyObjsCommand", fromUri, destUri, setMimeType, cannedAcl )
    invisible( NULL )
}



# Implements mv (move) command on GS storage

gs.mv <- function( fromUri, destUri, setMimeType = FALSE, cannedAcl = NULL ){

    if( !exists( ".gsutil" ) )
        stop( "You need to connect to GS using function gs.connect first" )

    if( !is.list( fromUri ) ) fromUri <- as.list( fromUri )
    #if( !is.list( destUri ) ) destUri <- as.list( destUri )

    jython.call( .gsutil, "MoveObjsCommand", fromUri, destUri, setMimeType, cannedAcl )
    invisible( NULL )
}


# Implements the getacl command on GS storage

gs.getacl <- function( uri ){

    if( !exists( ".gsutil" ) )
        stop( "You need to connect to GS using function gs.connect first" )

    jython.call( .gsutil, "GetAclCommand", uri )
}


# Saves an R object into GS

gs.save <- function( uri, ... ){

    if( !exists( ".gsutil" ) )
        stop( "You need to connect to GS using function gs.connect first" )

    dest.file <- tempfile()
    save( file = dest.file, ... )
    gs.mv( dest.file, uri )
}


# Saves R image into GS

gs.save.image <- function( uri, ... ){

    if( !exists( ".gsutil" ) )
        stop( "You need to connect to GS using function gs.connect first" )

    dest.file <- tempfile()
    save.image( file = dest.file, ... )
    gs.mv( dest.file, uri )
}


# Loads an R file into R

gs.load <- function( uri, ... ){

    if( !exists( ".gsutil" ) )
        stop( "You need to connect to GS using function gs.connect first" )

    if( !exists( env ) )
        env = parent.env( environment() )

    load.args <- list()
    load.args[["envir"]] <- env

    dest.file <- tempfile()
    gs.cp( uri, dest.file )
    do.call( load, c( list( file = dest.file, load.args ) ) )
    ulink( dest.file )
}


