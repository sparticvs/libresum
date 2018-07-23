# LibreSUM
A completely free to use checksum program. This implements the following
checksum algorithms:
  - SHA-224 (FIPS 180-4)
  - SHA-256 (FIPS 180-4)
  - SHA-384 (FIPS 180-4)
  - SHA-512 (FIPS 180-4)

The goal is to implement all of these:
  - SHA1 (FIPS 180-4)
  - SHA-512/224 (FIPS 180-4)
  - SHA-512/256 (FIPS 180-4)
  - SHA3-224 (FIPS 202)
  - SHA3-256 (FIPS 202)
  - SHA3-384 (FIPS 202)
  - SHA3-512 (FIPS 202)

## Where is md5sum?
If there is enough people that complain, maybe I'll implement, but I am going
to refrain since it's too easy to do a collision attack against it.

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
Depending how the binary is called (for instance it's name) is how it will act.
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

## Roadmap
I'd like to start giving people a general understanding of the roadmap for this project.

### v0.1 (Released)

#### Features
- SHA-256 Support
- Multi-file summing support
- Multiple-Entry Binary support

### v0.2 (Released)

#### Features
- SHA-512 Support
- Add BSD output capability

### v0.3 (Released)

The purpose of this release is to add additional functionality to validate the
API's implementation strategy as well as provide much needed validation
support.

#### Features
- SHA-224
- SHA-384
- Checksum validation

### v0.4 (In-Progress)

The ultimate goal of this release is to start to transition the hashing
functionality and APIs off into a separate library that will allow for
better code coverage testing.

#### Features
- SHA-1 Support
- SHA Family Library extraction
- Unit Test Code Coverage min of 50%

### v0.5 (Planned)

Features will be flowed into this project from the newly segregated library.

#### Features
- SHA512/224 Support
- SHA512/256 Support
- Unit Test Code Coverage min of 75%
