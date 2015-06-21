# Password Safe

Read/Write original [Password Safe](http://pwsafe.org) v3 files.

## Build

Build with [gb](http://getgb.io)

## Use
Password Safe for the command line.

```sh
    pwsafe -f passwords.psafe3
```

## Caveat

Support for the file is minimal. You may lose some field or header data.
Only the main field types are supported (Title,Group,User,Pass,Url,Email).

Seems to work well with the [Android](https://play.google.com/store/apps/details?id=com.jefftharris.passwdsafe) application.

