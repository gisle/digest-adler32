require 5.004;
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME         => "Digest::Adler32",
   VERSION_FROM => "lib/Digest/Adler32.pm",
   dist         => { COMPRESS => 'gzip -9f', SUFFIX => 'gz'},
);
