# Changelog

## [1.2.0] - Upcoming

* CHANGE Any decrypt method returns original value in case when given value is not surrounded by braces "{" and "}".
* CHANGE Exception class GeneralSecurityException replaced by runtime exception SimpleCryptException
* FEATURE Method "init()" added to create settings file if it doesn't exist. Recommend to call during application start.

## [1.1.2] - 2021-12-17
* BUGFIX Log4shell issue fixed

## [1.1.1] - 2021-03-17

* BUGFIX Possible NPE occur on empty arguments 
* FEATURE Set alternative default settings file

## [1.0.1] - 2021-03-08

* FEATURE Initial release