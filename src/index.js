import cors from 'cors';
import express from 'express';
import bodyParser from 'body-parser';
import 'dotenv/config';
import uuidv4 from 'uuid/v4';

import models from './models';


const app = express();

app.use(cors()); // all routes are extended with CORS HTTP headers. By default all routes are accessible for all domains now.

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use((req, res, next) => {
    req.context = {
        models,
        me: models.users[1],
    };
    next();
});


app.get('/', (req, res) => {
    return res.send('Received a GET HTTP method');
});

app.get('/session', (req, res) => {
    return res.send(req.context.models.users[req.context.me.id]);
});

app.get('/users', (req, res) => {
    return res.send(Object.values(req.context.models.users));
});

app.get('/users/:userId', (req, res) => {
    return res.send(req.context.models.users[req.params.userId]);
});

app.get('/messages', (req, res) => {
    return res.send(Object.values(req.context.models.messages));
});

app.get('/messages/:messageId', (req, res) => {
    return res.send(req.context.models.messages[req.params.messageId]);
});


app.post('/', (req, res) => {
    return res.send('Received a POST HTTP method');
});

app.post('/messages', (req, res) => {
    const id = uuidv4();
    const message = {
        id,
        text: req.body.text,
        userId: req.context.me.id,
    };

    req.context.models.messages[id] = message;

    return res.send(message);
});


app.put('/', (req, res) => {
    return res.send('Received a PUT HTTP method');
});


app.delete('/messages/:messageId', (req, res) => {
    const {
        [req.params.messageId]: message,
        ...otherMessages
    } = req.context.models.messages;

    req.context.models.messages = otherMessages;

    return res.send(message);
});


app.listen(process.env.PORT, () =>
    console.log(`Example app listening on port ${process.env.PORT}!`),
);


console.log('Hello Node.js project');
console.log(process.env.MY_SECRET);
