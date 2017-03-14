var express = require('express');
var passport = require('passport');

var LocalStrategy = require('passport-local').Strategy;

var router = express.Router();

var User = require('../models/users');

// Register
router.get('/register', function (req, res) {
	res.render('register');
});


// Login
router.get('/login', function (req, res) {
	res.render('login');
});

// Register User
router.post('/register', function (req, res) {
	var name = req.body.name;
	var email = req.body.email;
	var username = req.body.username;
	var password = req.body.password;
	var password2 = req.body.password2;

	//console.log(name +" "+ email +" "+ username +" "+ password +" "+ password2);

	//Validation
	req.checkBody('name','El nombre es requerido').notEmpty();
	req.checkBody('email','El correo es requerido').notEmpty();
	req.checkBody('email','No es un correo').isEmail();
	req.checkBody('username','El nombre de usuario es requerido').notEmpty();
	req.checkBody('password','La contraseña es requerida').notEmpty();
	req.checkBody('password2','Las contraseñas no coinciden').equals(password);

	var errors = req.validationErrors();

	if (errors) {
		res.render('register',{
			errors: errors
		});
	} else {
		var newUser = new User({
			name: name,
			email: email,
			username: username,
			password: password
		});
		User.createUser(newUser, function(err, user) {
			if(err) throw err;
			console.log(user);
		});
		req.flash('success_msg', 'Usuario creado');
		res.redirect('/users/login');

	}

});

passport.use(new LocalStrategy(
  function(username, password, done) {
   User.getUserByUsername(username, function(err, user){
   	if(err) throw err;
   	if(!user){
   		return done(null, false, {message: 'Usuario desconocido'});
   	}

   	User.comparePassword(password, user.password, function(err, isMatch){
   		if(err) throw err;
   		if(isMatch){
   			return done(null, user);
   		} else {
   			return done(null, false, {message: 'Contraseña invalida'});
   		}
   	});
   });
  }));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

router.post('/login',
	  passport.authenticate('local', {successRedirect:'/', failureRedirect:'/users/login',failureFlash: true, badRequestMessage:'Ingrese usuario y contraseña'}),
	  function(req, res) {
	  	var username = req.body.username;
		var password = req.body.password;
		console.log(username +" - "+  password );
	  	//Validation
		req.checkBody('username','El nombre de usuario es requerido').notEmpty();
		req.checkBody('password','La contraseña es requerida').notEmpty();

		var errors = req.validationErrors();

		if (errors) {
			res.render('login',{
				errors: errors
			});
		} else {

	  	

	  	res.redirect('/');
	    
	    }

	  });

router.get('/logout', function(req, res){
	req.logout();

	req.flash('success_msg', 'Cerraste sesión');

	res.redirect('/users/login');

});

module.exports = router;