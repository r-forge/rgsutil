\name{gs.mb}
\alias{gs.mb}
\alias{gs.rb}
%- Also NEED an '\alias' for EACH other topic documented here.
\title{ Functions for creating and removing remote buckets }
\description{
    These functions allow the user to create and remove buckets.
}
\usage{
    gs.mb(files = "gs://")
    gs.rb(files = NULL)
}
%- maybe also 'usage' for other objects documented here.
\arguments{
  \item{files}{ Name of the bucket to be created or removed }
}
\details{
    Buckets are containers of files on Google Storage. 
    These cannot contain other buckets.

    These two functions allow the user to create and remove them.
}
\author{
    Carlos J. Gil Bellosta
}

\examples{
}
\keyword{ manip }
