# LibreSUM
A completely free to use checksum program. This implements the following
checksum algorithms:
  - SHA-256 (FIPS 180-2)

The goal is to implement all of these:
  - SHA1
  - SHA-224
  - SHA-384
  - SHA-512
  - SHA-512/224
  - SHA-512/256
  - SHA3-224
  - SHA3-256
  - SHA3-384
  - SHA3-512

## Why?
Because some things shouldn't be GPL. This is one of those things. Everything
is MIT. See LICENSE file.

## Is it secure?
Should be. Code is clean and commented, so you should be able to understand
what is going on.

## Found a bug/vuln?
File it. No need to be secretive about it.

## Requirements
    cmake >= 2.6

## Building
Easy peasy.

    $ mkdir build
    $ cd build
    $ cmake ..
    $ make
    $ make install

## Developing
I probably won't accept commits. I have really high standards as to how code
should be written.

## Multiple Entry Application (Planned)
Depending how the binary is called (for instance it's name) it how it will act.
The point of this is that you don't need to configure aliases or wrapper
scripts, just use a soft link to the program named as the program you want.

Example would be, if you create a link pointing to `libresum` and name it
`sha256sum`, then the `sha256sum` code will run automatically.

## Validation
This hasn't been validated by anyone. If you are a company that is going to get
this validated, please let me know. I'd love to work with you to get the
certification status into the codebase, so contact me on GitHub.

## How do I know you didn't just copy GNU...
Well you just have to trust me. I wrote this following the spec and validated
it was operating correctly against NESSIE's test vectors.
