\name{gs.save}
\alias{gs.save}
\alias{gs.save.image}
\alias{gs.load}
\title{ Save/load R objects at/from remote destinations }
\description{
    Utility functions allowing the user to store R objects at a remote destinations and to restore them.
}
\usage{
gs.save(uri, ...)
gs.save.image(uri, ...)
gs.load(uri, ...)
}
\arguments{
  \item{uri}{ Destination file }
  \item{\dots}{ Other arguments passed to the underlying \code{save}, \code{save.image}, or \code{load} functions }
}
\details{
    These functions operate exactly as their undecorated counterparts, \code{save}, \code{save.image}, or \code{load}.
    However, they allow the user to save or load from a remote file.
}
\author{
    Carlos J. Gil Bellosta
}

\examples{
}
\keyword{ manip }
