import cors from 'cors';
import express from 'express';
import bodyParser from 'body-parser';
import 'dotenv/config';
import uuidv4 from 'uuid/v4';

import { users, messages } from './tmpData';


const app = express();

app.use(cors()); // all routes are extended with CORS HTTP headers. By default all routes are accessible for all domains now.

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use((req, res, next) => {
    req.me = users[1];
    next();
});  


app.get('/', (req, res) => {
    return res.send('Received a GET HTTP method');
});
app.get('/users', (req, res) => {
    return res.send(Object.values(users));
});

app.get('/users/:userId', (req, res) => {
    return res.send(users[req.params.userId]);
});

app.get('/messages', (req, res) => {
    return res.send(Object.values(messages));
});

app.get('/messages/:messageId', (req, res) => {
    return res.send(messages[req.params.messageId]);
});


app.post('/', (req, res) => {
    return res.send('Received a POST HTTP method');
});

app.post('/messages', (req, res) => {
    const id = uuidv4();
    const message = {
        id,
        text: req.body.text,
        userId: req.me.id,
    };

    messages[id] = message;

    return res.send(message);
});


app.put('/', (req, res) => {
    return res.send('Received a PUT HTTP method');
});


app.delete('/', (req, res) => {
    return res.send('Received a DELETE HTTP method');
});


app.listen(process.env.PORT, () =>
    console.log(`Example app listening on port ${process.env.PORT}!`),
);


console.log('Hello Node.js project');
console.log(process.env.MY_SECRET);
