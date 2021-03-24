//jshint esversion:6

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs  = require('ejs');
const mongoose = require("mongoose")
//const encrypt = require('mongoose-encryption')
//const md5 = require("md5") 
//const bcrypt = require('bcrypt')
//const saltRounds = 10;

const session = require('express-session')
const passport = require('passport')
const passportLocalMongoose = require('passport-local-mongoose')
//passport-local is required by mongoose-local-mongoose and no need to require it


const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')

const app = express();

app.use(bodyParser.urlencoded({extended:true}))
app.set('view engine','ejs')
app.use(express.static('public'))
 

//this must be just above the db connection
app.use(session({
     secret:"Our little secret.",
     resave:false,
     saveUninitialized: false
     }))

//this 2 lines must be under the session initialization
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser: true,useUnifiedTopology: true })
// to overcome an error
mongoose.set('useCreateIndex', true)

const userSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret: String

})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});

const User = new mongoose.model('User',userSchema)

// this 3 line come after  the model creation
// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });



// must be under session initialization and before routes
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
    //userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



 
app.get('/',function(req,res){
res.render('home')}
)


app.get('/auth/google',
    passport.authenticate('google', {scope:['profile']})
); 


app.get( '/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
}));

app.get('/register',function(req,res){
    res.render('register')
})


app.get('/login',function(req,res){
    res.render('login')
})

app.get('/submit',function(req,res){
    if(req.isAuthenticated()){
        res.render('submit');
    }else{
        res.redirect('/login')
    }
})

app.get('/secrets',function(req,res){
    /* if(req.isAuthenticated()){
        res.render('secrets');
    }else{
        res.redirect('/login')
    } */

    User.find({"secret":{$ne:null}},function(err,foundUsers){
           if(err){
               console.log(err);
           } else{
               res.render('secrets',{usersWithSecets:foundUsers})
           }
    })


}); 


app.listen(3000,function(){
    console.log("server started on port 3000");
})


app.post('/register',function(req,res){
    //this fct come from passport-local-mongoose
    User.register({username:req.body.username},req.body.password,function(err,user){
       if(err){
           console.log(err);
           res.redirect('/register');
       }else{
           passport.authenticate('local')(req,res,function(){
               res.redirect('/secrets');
           }) 
       }
   })
 })


 app.post('/login',function(req,res){
    const user = new User({
        username:req.body.username,
        password: req.body.password
    })

    req.login(user,function(err){
        if(err){
            log(err);
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect('/secrets');

            })
        }
    })



 })

 app.post("/submit",function(req,res){
     const submittedSecret = req.body.secret;
     console.log(req.user.id);
        User.findById(req.user.id,function(err,foundUser){
            if(err){
                log(err)
            }else{
                if(foundUser){
                    foundUser.secret = submittedSecret
                    foundUser.save(function(){
                        res.redirect('/secrets')
                    })
                }
            }
        })

 })


 app.get('/logout',function(req,res){
     req.logout();
     res.redirect('/')
 })













//using hash by bcrypt
/* app.post('/register',function(req,res){
    bcrypt.hash(req.body.password,saltRounds,function(err,hash){
        const newUser = new User({
            email:req.body.username,
            password : hash
        })
    
        newUser.save(function(err){
            if(err){
                console.log(err);
            }else{
                res.render('secrets');
            }
        });
    
    });
 }) */

 //login by hash and bcrypt
/* app.post('/login',function(req,res){
    const username = req.body.username;
    const password = req.body.password;
    User.findOne({email:username},function(err,foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
               bcrypt.compare(password,foundUser.password,function(err,result){
                    if(result===true){
                        res.render('secrets')
                    }else{
                        console.log("password is wrong !!");
                    }
               })
            }
        }
    })

}) */