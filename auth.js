const passport = require('passport');
const expressSession = require('express-session');
const LocalStrategy = require('passport-local');
const crypto = require('crypto');

const userModel = require('./user/model');

module.exports = app => {
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) => {
    userModel.get({ id }).then(
      user => {
        if (!user) {
          done('user not found');
        }
        else{
	  done(null, user);
	}
      },
      err => done(err),
    );
  });

  passport.use(
    new LocalStrategy((username, password, done) => {
      const hash = crypto
        .createHash('md5')
        .update(password)
        .digest('hex');
      userModel.get({ username, password: hash }).then(
        user => {
          if (!user) {
            done('user not found');
          }
          else{
	    done(null, user);
	  }
        },
        error => done(error),
      );
    }),
  );

  app.use(
    expressSession({
      secret: 'top secret',
      resave: false,
      saveUninitialized: false,
    }),
  );

  app.use(passport.initialize());
  app.use(passport.session());

  app.post(
    '/login',
    passport.authenticate('local', { failureRedirect: '/login.html' }),
    (request, response) => {
      response.redirect('/');
    },
  );
  app.get('/logout', function(req, res, next){
   req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
   });
  });
};
