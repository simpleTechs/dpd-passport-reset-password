var Email = require('../dpd-email'),
    AuthResource = require('../dpd-passport'),
    uuid = require('deployd/lib/util/uuid')
    _handle = AuthResource.prototype.handle;

AuthResource.events = AuthResource.events || [];
AuthResource.events.push("sendmail");

// add "allow passwort reset" as option to the dashboard 
AuthResource.basicDashboard.settings.push({
    name        : 'allowPasswortReset',
    type        : 'checkbox',
    description : 'Allow users to reset their password'
});
AuthResource.basicDashboard.settings.push({
    name        : 'passwortResetMandrillTemplate',
    type        : 'text',
    description : 'Mandrill-Template to use for sending emails. (requires dpd-email, you may use sendmail event instead!)'
});
AuthResource.basicDashboard.settings.push({
    name        : 'passwortResetMandrillSubaccount',
    type        : 'text',
    description : 'Mandrill-Subaccount to use for sending emails. (requires dpd-email, you may use sendmail event instead!)'
});

AuthResource.prototype.initPasswortReset = function() {
    if(this.dpd) return;
    this.dpd = require('deployd/lib/internal-client').build(process.server, {isRoot: true}, []);
}

var sendResponse = function(ctx, err, res) {
    if(err) {
        ctx.res.statusCode = 401;
        return ctx.done('cannot reset password');
    } else {
        return ctx.done(err, res);
    }
}

AuthResource.prototype.handle = function (ctx, next) {
    if(ctx.method === 'POST' && ctx.url === '/forgot-password') {
        this.initPasswortReset();
        var self = this, 
            dpd = this.dpd;

        var username = ctx.body.username;
        if(!username) return sendResponse(ctx, true);

        dpd.users.get({username: username}, function(users, err) {
            console.log(users);

            if(!users || !users.length) {
                // we don't want to expose that a certain user is in our db (or not), so we just return success here.
                return ctx.done(null, 'You will receive instructions via email.');
            }
            var user = users[0];
            
            // set a resetToken
            var resetToken = uuid.create(64);
            
            dpd.users.put({id: user.id, resetToken: resetToken}, function(res, err) {
                // send the mail
                console.log('Send...', resetToken);
                if(self.events.sendmail) {
                    var res;
                    self.events.sendmail.run(ctx, {
                        resetToken: token,
                        setResult: function(result) {
                            res = result;
                        },
                        template: self.config.passwortResetMandrillTemplate
                    }, function(err) {
                        ctx.done(err, res);
                    });
                } else {
                    dpd.email.post({
                        to: user.username,
                        headers: {
                            'X-MC-AutoHtml': true,
                            'X-MC-Subaccount': self.config.passwortResetMandrillSubaccount,
                            'X-MC-Template': self.config.passwortResetMandrillTemplate,
                            'X-MC-MergeVars': JSON.stringify({
                                'BASEURL': self.config.baseURL,
                                'TOKEN': resetToken
                            })
                        },
                        text:' '
                    }, function(res, err) {
                        console.log(err, res);
                        return ctx.done(err, 'You will receive instructions via email.');
                    });
                }
            });
        });
    } else if(ctx.method === 'POST' && ctx.url === '/reset-password') {
        this.initPasswortReset();

        var dpd = this.dpd;
        var username = ctx.body.username,
            password = ctx.body.password,
            confirmation = ctx.body.confirmation,
            token = ctx.body.token;

        if(!username || !password) return sendResponse(ctx, true);
        if(!(password===confirmation)) {
            ctx.res.statusCode = 401;
            return ctx.done('password must match confirmation');
        }

        dpd.users.get({ $and: [{username: username}, {resetToken: token}]}, function(users, err) {
            console.log(users);

            if(!users || !users.length) return sendResponse(ctx, true);
            var user = users[0];
            
            // delete the resetToken and update the password
            dpd.users.put({id: user.id, password: password, resetToken: ''}, function(res, err) {
                // end the request;
                return ctx.done(err, 'The password was successfully updated!');
            });
        });
    } else {
        // handover to original module
        return _handle.call(AuthResource.prototype, arguments);
    }
}