## Auth-Passport-Password-Reset Extension

This extensions adds password-reset by mail to `dpd-passport`.

### Requirements

* deployd (you'd have guessed that, probably :-))
* `dpd-passport`
* `dpd-email`
* A Mandrill Account

### Installation

In your app's root directory, type `npm install dpd-passport-password-reset` into the command line or [download the source](https://bitbucket.org/simpletechs/dpd-passport-password-reset). This should create a `dpd-passport-password-reset` directory in your app's `node_modules` directory.

See [Installing Modules](http://docs.deployd.com/docs/using-modules/installing-modules.md) for details.

### Setup

Open your Dashboard and open the Passport-Auth Resource. 
Then configure the Mandrill Account you want to use for sending out emails.

### Usage

Provide a `form` that `POST`s to `/auth/forgot-password`, where `auth` needs to be the name of your Passport-Auth Resource.
As a parameter you need to supply the `username`. The extension will then go ahead and use `dpd-email` to send out an email to Mandrill, which will in turn use your template and send it to the user.

### Development

To get started with development, please fork this repository and make your desired changes. Please note that we do all our dev work on bitbucket, so while you may submit pull requests on github, we will only push releases to github once they are finished.

### Credits

Auth-Passport-Password-Reset is the work of [simpleTechs.net](https://www.simpletechs.net)