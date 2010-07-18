# cjgb, 20100702: ListCommand modificado
# cjgb, 20100702: PrintObjectMetaData modificado
# cjgb, 20100702: CreateBotoConfigFile modificado
# cjgb, 20100702: ver forma de gestionar la lectura y comprobacion de credenciales
# cjgb, 20100702: comprobar que tiene "file uris" en ciertas operaciones en R
# OutputUsageAndExit, MakeBucketsCommand, RemoveBucketsCommand modificado

"""Google Storage command line tool."""

import datetime
import fnmatch
import getopt
import glob
import mimetypes
import os
import platform
import re
import shutil
import signal
import stat
import sys
import tarfile
import tempfile
import xml.dom.minidom

import boto
from boto import handler
from boto.exception import BotoClientError
from boto.exception import InvalidAclError
from boto.exception import InvalidUriError
from boto.exception import S3ResponseError


class RError(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

def OutputUsageAndExit():
  raise RError(usage_string)


def StorageUri(uri_str, disallow_object_name=False, debug=False):
  """Instantiate boto.StorageUri with given debug flag with validity checks.

  Args:
    uri_str: StorageUri naming bucket + optional object.
    disallow_object_name: Set to true to only allow object name-less buckets.
    debug: Whether to enable debugging on StorageUri method calls.

  Returns:
    boto.StorageUri for given uri_str.

  Raises:
    InvalidUriError: if uri_str not valid.
  """

  uri = boto.storage_uri(uri_str, 'file', debug)
  if disallow_object_name and uri.object_name:
    raise RError('Command requires a URI with no object name')
  if uri.bucket_name and re.search('[*?\[\]]', uri.bucket_name):
    raise RError('Bucket names cannot contain wildcards')
  return uri


def ExpandStorageUriGlob(bucket_obj_glob, headers=None, debug=False):
  """Expands globbing (if any) in bucket_obj_glob.

  Args:
    bucket_obj_glob: bucket+object name, possibly including glob chars.
    headers: dictionary containing optional HTTP headers to pass to boto.
    debug: flag indicating whether to include debug output

  Returns:
    list of boto.StorageUri, after expanding any globbing.

  For example, ExpandStorageUriGlob('gs://mybucket/*.txt', headers, debug)
  might return [StorageUri('gs://mybucket/obj1.txt'),
                StorageUri('gs://mybucket/obj2.txt')]
  """

  uri = StorageUri(bucket_obj_glob, False, debug)
  key_glob = uri.object_name
  result = []
  # Avoid server round trip if input contains no glob chars.
  if not re.search('[*?\[\]]', key_glob):
    result.append(uri)
  elif uri.is_file_uri():
    # FileStorageUri objects don't provide a way to return a list of all
    # files in the 'bucket', so do our own wildcard expansion for that case.
    filenames = glob.glob(uri.object_name)
    for filename in filenames:
      expanded_uri = uri.clone_replace_name(filename)
      result.append(expanded_uri)
  else:
    # BucketStorageUri with wildcarding.
    objs = uri.get_bucket(False, headers)
    for obj in objs:
      if fnmatch.fnmatch(obj.name, key_glob):
        # Replace wildcard name in URI with specific matched obj.name
        expanded_uri = uri.clone_replace_name(obj.name)
        result.append(expanded_uri)
  return result


def ExpandWildcardsAndContainers(uri_strs, headers=None, debug=False):
  """Expands any URI globbing, object-less bucket names, or directory names.

  Args:
    uri_strs: URI strings needing expansion
    headers: dictionary containing optional HTTP headers to pass to boto.
    debug: flag indicating whether to include debug output

  Returns:
    list of boto.StorageUri, after expanding any globbing and recursively
    walking directories.
  """

  result = []
  for uri_str in uri_strs:
    for exp_uri in ExpandStorageUriGlob(uri_str, headers, debug):
      if exp_uri.is_file_uri() and exp_uri.names_container():
        # exp_uri is a file:// URI that names a directory, so include
        # all its nested files.
        for root, unused_dirs, files in os.walk(exp_uri.object_name):
          for name in files:
            result.append(StorageUri(os.path.join(root, name)))
      elif exp_uri.is_cloud_uri() and exp_uri.names_container():
        # exp_uri is an object-less bucket URI, so include
        # all its nested objects.
        bucket_wildcard = exp_uri.clone_replace_name('*').uri
        uris = ExpandStorageUriGlob(bucket_wildcard, headers, debug)
        for uri in uris:
          result.append(uri)
      else:
        result.append(exp_uri)
  return result


def InsistUriNamesContainer(command, uri):
  """Prints error and exists if URI doesn't name a directory or bucket.

  Args:
    command: command being run
    uri: StorageUri to check
  """

  if uri.names_singleton():
    OutputAndExit('destination StorageUri must name a bucket or directory '
                  'for the multiple source\nform of the "%s" command.' %
                  command)



def SetAclCommand(args, headers=None, debug=False):
  """Implementation of setacl command.

  Args:
    args: command-line arguments
    unused_sub_opts: command-specific options from getopt.
    headers: dictionary containing optional HTTP headers to pass to boto.
    debug: flag indicating whether to include debug output
  """

  acl_arg = args[0]
  # Expand object name globs, if any.
  exp_uris = []
  for uri_str in args[1:]:
    for exp_uri in ExpandStorageUriGlob(uri_str, headers, debug):
      exp_uris.append(exp_uri)

  # Disallow setacl command spanning multiple providers because
  # there are differences in the ACL models.
  provider = None
  for uri in exp_uris:
    if not provider:
      provider = uri.provider
    elif uri.provider != provider:
      OutputAndExit('"setacl" command spanning multiple providers not allowed.')

  # Get ACL object from connection for the first URI, for interpreting the
  # ACL.  This won't fail because the main startup code insists on 1 arg
  # for this command.
  storage_uri = exp_uris[0]
  acl_class = storage_uri.acl_class()
  canned_acls = storage_uri.canned_acls()

  # Determine whether acl_arg names a file containing XML ACL text vs. the
  # string name of a canned ACL.
  if os.path.isfile(acl_arg):
    acl_file = open(acl_arg, 'r')
    acl_txt = acl_file.read()
    acl_file.close()
    acl_obj = acl_class()
    h = handler.XmlHandler(acl_obj, storage_uri.get_bucket())
    try:
      xml.sax.parseString(acl_txt, h)
    except xml.sax._exceptions.SAXParseException, e:
      OutputAndExit('Requested ACL is invalid: %s at line %s, column %s' %
                    (e.getMessage(), e.getLineNumber(), e.getColumnNumber()))
    acl_arg = acl_obj
  else:
    # No file exists, so expect a canned ACL string.
    if acl_arg not in canned_acls:
      OutputAndExit('Invalid canned ACL "%s".' % acl_arg)

  # Now iterate over URIs and set the ACL on each.
  for uri in exp_uris:
    uri.set_acl(acl_arg, uri.object_name, False, headers)


def LoadVersionString():
  """Loads version string for currently installed gsutil command.

  Returns:
    Version string.
  """

  ver_file_path = gsutil_bin_dir + os.sep + 'VERSION'
  if not os.path.isfile(ver_file_path):
    OutputAndExit('%s not found. Did you install the\ncomplete gsutil software '
                  'after the gsutil "update" command was implemented?' %
                  ver_file_path)
  ver_file = open(ver_file_path, 'r')
  installed_version_string = ver_file.read().rstrip('\n')
  ver_file.close()
  return installed_version_string


def CheckForDirFileConflict(src_uri, dst_path):
  """Checks whether copying src_uri into dst_path is not possible.

     This happens if a directory exists in local file system where a file needs
     to go or vice versa.  In that case we print an error message and exits.
     Example: if the file "./x" exists and you try to do:
       gsutil cp gs://mybucket/x/y .
     the request can't succeed because it requires a directory where
     the file x exists.

  Args:
    src_uri: source StorageUri of copy
    dst_path: destination path.
  """

  final_dir = os.path.dirname(dst_path)
  if os.path.isfile(final_dir):
    OutputAndExit('Cannot retrieve %s because it a file exists where a '
                  'directory needs to be created (%s).' % (src_uri, final_dir))
  if os.path.isdir(dst_path):
    OutputAndExit('Cannot retrieve %s because a directory exists '
                  '(%s) where the file needs to be created.' %
                  (src_uri, dst_path))


def ReportNoMatchesAndExit(uri):
  """Reports no URI wildcard matches and exits.

  Args:
    uri: the StorageUri that didn't match.
  """
  if uri.is_file_uri():
    OutputAndExit('"%s" matches no files.' % uri.uri)
  else:
    OutputAndExit('"%s" matches no objects.' % uri.uri)


def GetAclCommand(args, headers=None, debug=False):
  """Implementation of getacl command.

  Args:
    args: command-line arguments
    unused_sub_opts: command-specific options from getopt.
    headers: dictionary containing optional HTTP headers to pass to boto.
    debug: flag indicating whether to include debug output
  """

  # Wildcarding is allowed but must resolve to just one object.
  uris = ExpandStorageUriGlob(args[0], headers, debug)
  if len(uris) != 1:
    OutputAndExit('Wildcards must resolve to exactly one object for "getacl" '
                  'command.')
  uri = uris[0]
  if not uri.bucket_name:
    OutputAndExit('"getacl" command must specify a bucket or object.')
  acl = uri.get_acl(False, headers)
  # Pretty-print the XML to make it more easily human editable.
  parsed_xml = xml.dom.minidom.parseString(acl.to_xml())
  return parsed_xml.toprettyxml(indent='    ')


def PerformCopy(src_uri, dst_uri, setMimeType, setCannedAcl, headers):
  """Helper method for CopyObjsCommand.

  Args:
    src_uri: source StorageUri for copy.
    dst_uri: destination StorageUri for copy.
    sub_opts: command-specific options from getopt.
    headers: dictionary containing optional HTTP headers to pass to boto.
  """

  # Make a copy of the input headers each time so we can set a different
  # MIME type for each object.
  metadata = headers.copy()
  canned_acl = None

  #if setCannedAc:
  #  canned_acls = dst_uri.canned_acls()
  #  if a not in canned_acls:
  #    OutputAndExit('Invalid canned ACL "%s".' % a)
  #  canned_acl = a

  if setMimeType:
    mimetype_tuple = mimetypes.guess_type(src_uri.object_name)
    mime_type = mimetype_tuple[0]
    content_encoding = mimetype_tuple[1]
    if mime_type:
      metadata['Content-Type'] = mime_type
      # print '\t[Setting Content-Type=%s]' % mime_type
    else:
      #print '\t[Unknown content type -> using application/octet stream]'
      pass
    if content_encoding:
      metadata['Content-Encoding'] = content_encoding

  src_key = src_uri.get_key(False, headers)
  if not src_key:
    OutputAndExit('"%s" does not exist.' % src_uri)

  # Separately handle cases to avoid extra file and network copying of
  # potentially very large files/objects.

  if (src_uri.is_cloud_uri() and dst_uri.is_cloud_uri() and
      src_uri.provider == dst_uri.provider):
    # Object -> object, within same provider (uses x-<provider>-copy-source
    # metadata HTTP header to request copying at the server). (Note: boto
    # does not currently provide a way to pass canned_acl when copying from
    # object-to-object through x-<provider>-copy-source):
    src_bucket = src_uri.get_bucket(False, headers)
    dst_bucket = dst_uri.get_bucket(False, headers)
    dst_bucket.copy_key(dst_uri.object_name, src_bucket.name,
                        src_uri.object_name, metadata)
    return

  dst_key = dst_uri.new_key(False, headers)
  if src_uri.is_file_uri() and dst_uri.is_cloud_uri():
    # File -> object:
    fname_parts = src_uri.object_name.split('.')
    dst_key.set_contents_from_file(src_key.fp, metadata, policy=canned_acl)
  elif src_uri.is_cloud_uri() and dst_uri.is_file_uri():
    # Object -> file:
    src_key.get_file(dst_key.fp, headers)
  elif src_uri.is_file_uri() and dst_uri.is_file_uri():
    # File -> file:
    dst_key.set_contents_from_file(src_key.fp, metadata)
  else:
    # We implement cross-provider object copy through a local temp file:
    tmp = tempfile.TemporaryFile()
    src_key.get_file(tmp, headers)
    tmp.seek(0)
    dst_key.set_contents_from_file(tmp, metadata)


def CopyObjsCommand( fromUri, destUri, setMimeType, cannedAcl, headers={}, debug=0):
  """Implementation of cp command.

  Args:
    args: command-line arguments
    sub_opts: command-specific options from getopt.
    headers: dictionary containing optional HTTP headers to pass to boto.
    debug: flag indicating whether to include debug output
  """

  src_uri_strs = fromUri
  dst_uri = StorageUri( destUri, False, debug)
  multi_obj_copy = True

  # Expand wildcards and containers in source StorageUris.
  exp_src_uris = ExpandWildcardsAndContainers(src_uri_strs, headers, debug)

  # Abort if wildcarding produced no matches.
  if not exp_src_uris:
    ReportNoMatchesAndExit(StorageUri(src_uri_strs[0]))

  # If there is 1 source arg after expansion, with src_uri naming an
  # object-less bucket and dst_uri naming a directory, handle two cases to
  # make copy command work like UNIX "cp -r" works:
  #   a) if no directory exists for dst_uri copy objects to a new directory
  #      with the dst_uri name, e.g., "bucket/a" -> "dir/a"
  #   b) if a directory exists for dst_uri copy objects to a new directory
  #      under that directory, e.g., "bucket/a" -> "dir/bucket/a"
  if len(exp_src_uris) == 1:
    src_uri_to_check = exp_src_uris[0]
    if src_uri_to_check.names_container():
      if dst_uri.names_container() and os.path.exists(dst_uri.object_name):
        dst_uri = dst_uri.clone_replace_name(dst_uri.object_name + os.sep +
                                             src_uri_to_check.bucket_name)
    else:
      multi_obj_copy = False

  if (multi_obj_copy and dst_uri.is_file_uri()
      and not os.path.exists(dst_uri.object_name)):
    os.makedirs(dst_uri.object_name)

  if multi_obj_copy:
    InsistUriNamesContainer('cp', dst_uri)

  # Abort if any source overlaps with a dest.
  for src_uri in exp_src_uris:
    if (src_uri.equals(dst_uri) or
        # Example case: gsutil cp gs://mybucket/a/bb mybucket
        (dst_uri.is_cloud_uri() and src_uri.uri.find(dst_uri.uri) != -1)):
      OutputAndExit('Overlapping source and dest URIs not allowed.')

  # Now iterate over expanded src URIs, and perform copy operations.
  for src_uri in exp_src_uris:
    if dst_uri.names_container():
      if dst_uri.is_file_uri():
        # dest names a directory, so append src obj name to dst obj name
        dst_key_name = dst_uri.object_name + os.sep + src_uri.object_name
        CheckForDirFileConflict(src_uri, dst_key_name)
      else:
        # dest names a bucket: use src obj name for dst obj name.
        dst_key_name = src_uri.object_name
    else:
      # dest is an object or file: use dst obj name
      dst_key_name = dst_uri.object_name
    new_dst_uri = dst_uri.clone_replace_name(dst_key_name)
    PerformCopy(src_uri, new_dst_uri, setMimeType, cannedAcl, headers)



def PrintObjectMetaData(uri, headers):
  """Print object metadata.

  Args:
    uri: object-granularity StorageUri
    headers: dictionary containing optional HTTP headers to pass to boto.
  """
  salida = []
  salida.append( '%s:' % uri )
  key = uri.get_key(False, headers)
  key.open_read()
  salida.append( '\tObject size:\t%s' % key.size )
  salida.append( '\tLast mod:\t%s' % key.last_modified )
  if key.cache_control:
    salida.append( '\tCache control:\t%s' % key.cache_control )
  salida.append( '\tMIME type:\t%s' % key.content_type )
  if key.content_encoding:
    salida.append( '\tContent-Encoding:\t%s' % key.content_encoding )
  salida.append( '\tMD5:\t%s' % key.etag.strip('"\'') )
  salida.append( '\tACL:\t%s' % uri.get_acl(False, headers) )
  return( salida )

def ListCommand(args, verbose=0, headers=None, debug=False):
  """Implementation of ls command.

  Args:
    args: command-line arguments
    sub_opts: command-specific options from getopt.
    headers: dictionary containing optional HTTP headers to pass to boto.
    debug: flag indicating whether to include debug output
  """

  long_listing = verbose == 1
  if not args:
	  args = ['gs://']		 # default to listing all gs buckets: TODO: comprobar en R

  # First expand all URIs into URIs in exp_args, such that:
  # a) provider-only URIs ('gs://') are left as-is.
  # b) bucket-only URIs ('gs://bucket') with -l option are left as bucket-only
  #    URIs.
  # c) bucket-only URIs ('gs://bucket') without -l option are replaced by
  #    the list of all the objects in the bucket.
  # d) complete URIs ('gs://bucket/obj') are replaced by the list of all of
  #    the matching objects names (handling URIs that contain wildcards,
  #    as well as wildcard-less URIs).
  exp_args = []
  for uri_str in args:
    uri = StorageUri(uri_str, False, debug)
    if not uri.bucket_name:
      exp_args.append(uri_str)				 # case a: provider-only URI
    elif not uri.object_name:
      if long_listing:
        exp_args.append(uri.__str__())			 # case b: bucket-only URI with -l option
      else:						 # case c: bucket-only URI without -l option
        bucket = uri.get_bucket(False, headers)
        for obj in bucket:
          exp_args.append(uri.clone_replace_name(obj.name).uri)
    else:						 # case d: complete URI
      regex = fnmatch.translate(uri.object_name)
      bucket = uri.get_bucket(False, headers)
      for obj in bucket:
        if re.match(regex, obj.name):
          exp_args.append(uri.clone_replace_name(obj.name).uri)

  # Handle the case of a complete URI that didn't match anything
  if uri.names_singleton() and not exp_args:
    return ""

  salida = []
  # Now iterate over all URIs in exp_args and print requested info for each
  for uri_str in exp_args:
    uri = StorageUri(uri_str, False, debug)
    if not uri.bucket_name:
      if long_listing:
        # Provider long listing: print metadata for all buckets
        buckets = uri.get_all_buckets()
        for bucket in buckets:
          bucket_uri = StorageUri(uri.provider + '://' + bucket.name, False, debug)
          salida.append( '%s:\n\tACL:\t%s' % (bucket_uri, bucket_uri.get_acl(False, headers)) )
      else:
        # Provider short listing: list all buckets

        buckets = uri.get_all_buckets()
        for bucket in buckets:
          bucket_uri = StorageUri(uri.provider + '://' + bucket.name, False, debug)
          salida.append( bucket_uri.__repr__() )
    elif not uri.object_name:
      if long_listing:
        salida.append( '%s:\n\tACL:' % uri )
        salida.append( '\t\t%s' % uri.get_acl(False, headers) )
      else:
        bucket = uri.get_bucket(False, headers)
        for obj in bucket:
          salida.append( '%s://%s/%s' % (uri.provider, uri.bucket_name, obj.name) )
    else:
      if long_listing:
        salida += PrintObjectMetaData(uri, headers)	 # Object long listing
      else:
        salida.append( uri.__repr__() )			 # Object short listing

  return( salida )


def MakeBucketsCommand(args, headers=None, debug=False):
  """Implementation of mb command.

  Args:
    args: command-line arguments
    unused_sub_opts: command-specific options from getopt.
    headers: dictionary containing optional HTTP headers to pass to boto.
    debug: flag indicating whether to include debug output
  """

  for bucket_uri_str in args:
    bucket_uri = StorageUri(bucket_uri_str, False, debug)
    bucket_uri.create_bucket(headers)


def MoveObjsCommand( fromUri, destUri, setMimeType, cannedAcl, headers={}, debug=0):
  """Implementation of mv command.

     Note that there is no atomic rename operation - this command is simply
     a shorthand for 'cp' followed by 'rm'.

  Args:
    args: command-line arguments
    sub_opts: command-specific options from getopt.
    headers: dictionary containing optional HTTP headers to pass to boto.
    debug: flag indicating whether to include debug output
  """

  # Refuse to delete a bucket or directory src URI (force users to explicitly
  # do that as a separate operation).
  src_uri_to_check = StorageUri( fromUri[0] )
  if src_uri_to_check.names_container():
    OutputAndExit('Will not remove source buckets or directories.  You should '
                  'separately copy and remove for that purpose.')

  InsistUriNamesContainer('mv', StorageUri( destUri ))

  CopyObjsCommand( fromUri, destUri, setMimeType, cannedAcl, headers, debug )
  RemoveObjsCommand(fromUri, headers, debug)


def RemoveBucketsCommand(args, headers=None, debug=False):
  """Implementation of rb command.

  Args:
    args: command-line arguments
    unused_sub_opts: command-specific options from getopt.
    headers: dictionary containing optional HTTP headers to pass to boto.
    debug: flag indicating whether to include debug output
  """

  for bucket_uri_str in args:
    bucket_uri = StorageUri(bucket_uri_str, True, debug)
    bucket_uri.delete_bucket(headers)


def RemoveObjsCommand(args, headers=None, debug=False):
  """Implementation of rm command.

  Args:
    args: command-line arguments
    headers: dictionary containing optional HTTP headers to pass to boto.
    debug: flag indicating whether to include debug output
  """

  # Expand object name globs, if any.
  exp_uris = []
  for uri_str in args:
    for exp_uri in ExpandStorageUriGlob(uri_str, headers, debug):
      exp_uris.append(exp_uri)
  for uri in exp_uris:
    if uri.names_container():
      OutputAndExit('"rm" command will not remove buckets.  To delete this '
                    'bucket do:\n\tgsutil rm %s/*\n\tgsutil rb %s' %
                    (uri.uri, uri.uri))
    uri.delete_key(False, headers)


def CreateBotoConfigFile( access_key, secret_access_key ):
  """Creates a boto config file interactively, containing needed credentials."""

  if 'HOME' in os.environ:
    config_path = ('%s%s.boto' % (os.environ['HOME'], os.sep))
  else:
    config_path = ('.%s.boto' % os.sep)

  provider_map = {'Amazon': 'aws', 'Google': 'gs'}
  uri_map = {'Amazon': 's3', 'Google': 'gs'}
  key_ids = {}
  sec_keys = {}
  for provider in provider_map:
    if provider == 'Google':
      key_ids[provider] = access_key
      sec_keys[provider] = secret_access_key
  cfp = open(config_path, 'w')
  if not cfp:
    OutputAndExit('Unable to write "%s".' % config_path)
  os.chmod(config_path, stat.S_IRUSR | stat.S_IWUSR)
  #cfp.write(prelude_config_content)
  #cfp.write('# This file was created by gsutil version "%s"\n# at %s.\n\n\n'
  #          % (LoadVersionString(),
  #             datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
  cfp.write('[Credentials]\n\n')
  for provider in provider_map:
    prefix = provider_map[provider]
    uri_scheme = uri_map[provider]
    if provider in key_ids and provider in sec_keys:
      cfp.write('# %s credentials ("%s://" URIs):\n' % (provider, uri_scheme))
      cfp.write('%s_access_key_id = %s\n' % (prefix, key_ids[provider]))
      cfp.write('%s_secret_access_key = %s\n' % (prefix, sec_keys[provider]))
    else:
      cfp.write('# To add %s credentials ("%s://" URIs), edit and '
                'uncomment the\n# following two lines:\n'
                '#%s_access_key_id = <your %s access key ID>\n'
                '#%s_secret_access_key = <your %s secret access key>\n' %
                (provider, uri_scheme, prefix, provider, prefix, provider))
    cfp.write('# The ability to specify an alternate storage host is primarily '
              'for developers.\n'
              '#%s_host = <alternate storage host address>\n\n' % (prefix))
  additional_config_content = """

[Boto]

# To use a proxy, edit and uncomment the proxy and proxy_port lines.  If you
# need a user/password with this proxy, edit and uncomment those lines as well.
#proxy = <proxy host>
#proxy_port = <proxy port>
#proxy_user = <your proxy user name>
#proxy_pass = <your proxy password>

# Set 'is_secure' to False to cause boto to connect using HTTP instead of the
# default HTTPS.  This is useful if you want to capture/analyze traffic
# (e.g., with tcpdump).
#is_secure = False

# 'debug' controls the level of debug messages printed: 0 for none, 1
# for basic boto debug, 2 for all boto debug plus HTTP requests/responses.
# Note: 'gsutil -d' sets debug to 2 for that one command run.
#debug = <0, 1, or 2>

# 'num_retries' controls the number of retry attempts made when errors occur.
# The default is 5.
#num_retries = <integer value>
"""

  cfp.write(additional_config_content)
  cfp.close()


def SetupConfigIfNeeded():
  """Interactively creates boto credential/config file if needed."""

  config = boto.config
  has_goog_creds = (config.has_option('Credentials', 'gs_access_key_id') and
                    config.has_option('Credentials', 'gs_secret_access_key'))
  return has_goog_creds


NO_MAX = sys.maxint
commands = {
    'cp': [CopyObjsCommand, 2, NO_MAX, 'a:tz:', True, False, 0],
    'getacl': [GetAclCommand, 1, 1, '', False, False, 0],
    'ls': [ListCommand, 0, NO_MAX, 'l', False, True, 0],
    'mb': [MakeBucketsCommand, 1, NO_MAX, '', False, False, 0],
    'mv': [MoveObjsCommand, 2, NO_MAX, '', True, False, 0],
    'rb': [RemoveBucketsCommand, 1, NO_MAX, '', False, False, 0],
    'rm': [RemoveObjsCommand, 1, NO_MAX, '', False, False, 0],
    'setacl': [SetAclCommand, 2, NO_MAX, '', False, False, 1],
}
