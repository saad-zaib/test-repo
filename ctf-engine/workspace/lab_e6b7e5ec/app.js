const express = require('express');
const mongoose = require('mongoose');

mongoose.connect('mongodb://db:27017/ctf');

const User = mongoose.model('User', new mongoose.Schema({
  username: String,
  password: String,
  flag: String
}));

User.create({ username: "admin", password: "SUPER_SECRET_COMPLEX_PASSWORD_123", flag: "CTF{mong0db_byp4ss3d_succ3ssfully_2024}" });

const app = express();
app.use(express.json());

app.post('/login', async (req, res) => {
    const user = await User.findOne({ 
        username: req.body.username,
        password: req.body.password 
    });
    
    if (user) return res.send("Welcome Admin! " + user.flag);
    return res.status(401).send("Invalid");
});

app.listen(3000, '0.0.0.0', () => console.log('Listening on 0.0.0.0:3000'));
