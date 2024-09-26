const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); 
const bcrypt = require('bcryptjs');
const {findBy} = require('../users/users-model'); 
const User = require('../users/users-model');
const jwt = require('jsonwebtoken');


router.post("/register", validateRoleName, (req, res, next) => {
const {username, password} = req.body
const {role_name} = req
const hash = bcrypt.hashSync(password, 8);
User.add({username, password: hash, role_name})
.then(n => {
  res.status(201).json(n)
})
.catch(next)
});





router.post("/login", checkUsernameExists, async (req, res, next) => {
if(bcrypt.compareSync(req.body.password, req.user.password)){
const token = buildToken(req.user)
res.json({
  message: `${req.user.username} is back!`,
  token,
})
}
else {
  next({status: 401, message: "Invalid credentials"})
}
 
})
    
 

const buildToken = (user) => {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const options = {
    expiresIn: '1d', 
  };
  return jwt.sign(payload, JWT_SECRET, options);
};

module.exports = router;
