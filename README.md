PHP Two Factor Authentication
========================

This code can be used to add two-factor authentication support to a PHP web app, using something like Google Authenticator.

The way it works is simple. First, the user registers a user name and is given a hash which has to be registered in the mobile authenticator. This can be done manually or through scanning of a QR code. Then, when logging in, the user presses a button to generate a new number, and the server tests 10 instances in case the mobile authenticator becomes unsynced a bit. It also provides a reset key as a backup code in case the mobile authenticator is lost. Everything is stored in a SQLite database.