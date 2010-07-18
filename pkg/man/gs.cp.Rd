\name{gs.cp}
\alias{gs.cp}
\alias{gs.ls}
\alias{gs.mv}
\alias{gs.rm}
\title{ Utility functions to list, copy, move, and delete remote files }
\description{
    These functions allow the user to perform basic operations with remote (and also local) files.
}
\usage{
    gs.cp(fromUri, destUri, setMimeType = FALSE, cannedAcl = NULL)
    gs.rm(files = NULL)
    gs.mv(fromUri, destUri, setMimeType = FALSE, cannedAcl = NULL)
    gs.ls(files = "gs://", verbose = 0, show = TRUE)
}
\arguments{
  \item{fromUri}{ Uri of the object or objects to be copied; these can contain expresions expanding to multiple files, such as \code{*.jpg} or the like }
  \item{destUri}{ Destination uri: it can be a non-existen file, a remote bucket or a local directory}
  \item{setMimeType}{ Unimplemented }
  \item{cannedAcl}{ Unimplemented }
  \item{files}{ List of files to be erased or listed; for the \code{gs.ls} command it can also be a bucket whose contents are to be listed }
  \item{verbose}{ Level of verbosity in listings }
  \item{show}{ TBA }
}
\references{
%% ~put references to the literature/web site here ~
}
\author{
    Carlos J. Gil Bellosta
}
\note{
%%  ~~further notes~~
}

\examples{
}
\keyword{ manip }
