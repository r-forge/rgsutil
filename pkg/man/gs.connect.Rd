\name{gs.connect}
\alias{gs.connect}
\title{ Function that opens a connection to Google Storage }
\description{
    This function allows the user to open a connection to Google Storage.
}
\usage{
gs.connect(access.key = NULL, secret.access.key = NULL)
}
\arguments{
  \item{access.key}{ Access key provided by Google to use Google Storage }
  \item{secret.access.key}{ Secret access key provided by Google to use Google Storage }
}
\details{
    Users need to be registered to use Google Storage. 
    Registered users recive a keypair that is stored somewhere in their system the first time they connect to the service.
    Typically, this location is the \code{.boto} file at their home directory.

    An user not having connected the service before will have to provide his keys to this function.
    The function will store them in the \code{.boto} file in his home directory so that these are not required again.
}
\author{
    Carlos J. Gil Bellosta
}

\keyword{ manip }
