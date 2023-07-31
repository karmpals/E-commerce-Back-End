const express = require('express');
const server = express();
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser')
const productsRouters = require('./routes/Products');
const categoriesRouter = require('./routes/Categories')
const brandsRouter = require('./routes/Brands')
const userRouter = require('./routes/User')
const authRouter = require('./routes/Auth')
const cartRouter = require('./routes/Carts')
const orderRouter = require('./routes/Orders');
const { User } = require('./model/User');
const { isAuth, sanitizeUser, cookieExtractor } = require('./services/common');

const SECRET_KEY = 'SECRET_KEY';





const opts = {}
opts.jwtFromRequest = cookieExtractor;
opts.secretOrKey = SECRET_KEY;


server.use(cookieParser());

server.use(cors({
    exposedHeaders: ['X-Total-Count']
}));
server.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false

}));

server.use(express.static('build'));

server.use(passport.authenticate('session'));
server.use(express.json());
server.use('/products', isAuth(), productsRouters.router)
server.use('/brands', isAuth(), brandsRouter.router)
server.use('/categories', isAuth(), categoriesRouter.router)
server.use('/users', isAuth(), userRouter.router)
server.use('/auth', authRouter.router)
server.use('/cart', isAuth(), cartRouter.router)
server.use('/orders', isAuth(), orderRouter.router)


passport.use('local', new LocalStrategy(
    {usernameField:'email'},
    async function (email, password, done) {
        try {
            const user = await User.findOne({ email: email }).exec();
            if (!user) {
                done(null, false, { message: 'invalid credentials' })
            }
            crypto.pbkdf2(
                password,
                user.salt,
                310000,
                32,
                'sha256',
                async function (err, hashedPassword) {

                    if (!crypto.timingSafeEqual(user.password, hashedPassword)) {
                        return done(null, false, { message: 'invalid credentials' })

                    }
                    const token = jwt.sign(sanitizeUser(user), SECRET_KEY);
                    done(null, {token});


                })


        }
        catch (err) {
            done(err);
        }
    }
));

passport.use('jwt', new JwtStrategy(opts, async function (jwt_payload, done) {
    console.log({ jwt_payload })
    try {
        const user = await User.findOne({ id: jwt_payload.sub })
        if (user) {
            return done(null, sanitizeUser(user));
        } else {
            return done(null, false);
        }
    }
    catch (err) {
        return done(err, false);
    }

}));

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, { id: user.id, role: user.role });
    })
})

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});



main().catch(err => console.log(err))

async function main() {
    await mongoose.connect('mongodb://127.0.0.1:27017/ecommerce')
    console.log('db connected')
}

server.listen(8080, () => {
    console.log('server started')
})