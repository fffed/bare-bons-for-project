import cors from 'cors';
import express from 'express';
import 'dotenv/config';

import { users, messages } from './tmpData';


const app = express();

app.use(cors()); // all routes are extended with CORS HTTP headers. By default all routes are accessible for all domains now.

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
