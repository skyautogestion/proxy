// defining the server port
const port = 8000

// initializing installed dependencies
const express = require('express')
require('dotenv').config()
const axios = require('axios')
const app = express()
const cors = require('cors')
app.use(cors())

const { REACT_APP_URL_OSB, REACT_APP_USERNAME_OSB, REACT_APP_PASSWORD_OSB, REACT_APP_URL_INTERNO, REACT_APP_USER_INTERNO, REACT_APP_PASSWORD_INTERNO } = process.env;
const CONTENT_ACCEPT_JSON = { 'Content-type': 'application/json', 'Accept': 'application/json' };
const OSB_AUTH = { 'username': REACT_APP_USERNAME_OSB ?? '', 'password': REACT_APP_PASSWORD_OSB ?? ''}
const INTERNO_AUTH = { 'username': REACT_APP_USER_INTERNO ?? '', 'password': REACT_APP_PASSWORD_INTERNO ?? ''}

// listening for port
app.listen(port, ()=> console.log(`Server is running on ${port}` ))

app.get('/', (req,rest) => {
    return 'hello world';
})

// API request
app.post('/EnterpriseServices/Sel/Solicitud/generarQueja', (req,res)=> {   
    const options = {
        method: 'POST',
        url: REACT_APP_URL_OSB+'/EnterpriseServices/Sel/Solicitud/generarQueja',
        data: req,
        headers: CONTENT_ACCEPT_JSON,
        auth: OSB_AUTH
   };
   
    axios.request(options).then(function (response) {
        res.json(response.data);
    }).catch(function (error) {
        console.error(error);
    });
});

app.post('/EnterpriseServices/Sel/Solicitud/crearSugerencia', (req,res)=> {   
    const options = {
        method: 'POST',
        url: REACT_APP_URL_OSB+'/EnterpriseServices/Sel/Solicitud/crearSugerencia',
        data: req,
        headers: CONTENT_ACCEPT_JSON,
        auth: OSB_AUTH
   };
   
    axios.request(options).then(function (response) {
        res.json(response.data);
    }).catch(function (error) {
        console.error(error);
    });
});

app.post('/EnterpriseServices/Sel/Solicitud/Solicitud/responderEncuesta', (req,res)=> {   
    const options = {
        method: 'POST',
        url: REACT_APP_URL_OSB+'/EnterpriseServices/Sel/Solicitud/responderEncuesta',
        data: req,
        headers: CONTENT_ACCEPT_JSON,
        auth: OSB_AUTH
   };
   
    axios.request(options).then(function (response) {
        res.json(response.data);
    }).catch(function (error) {
        console.error(error);
    });
});

app.post('/EnterpriseServices/Sel/Solicitud/AltaSolicitudDeServicioRest', (req,res)=> {   
    const options = {
        method: 'POST',
        url: REACT_APP_URL_OSB+'/EnterpriseServices/Sel/AltaSolicitudDeServicioRest',
        data: req,
        headers: CONTENT_ACCEPT_JSON,
        auth: OSB_AUTH
   };
   
    axios.request(options).then(function (response) {
        res.json(response.data);
    }).catch(function (error) {
        console.error(error);
    });
});

app.post('/EnterpriseFlows/Sel/AutenticarUsuarioRest', (req,res)=> {   
    const options = {
        method: 'POST',
        url: REACT_APP_URL_INTERNO+'/EnterpriseFlows/Sel/AutenticarUsuarioRest',
        data: req,
        headers: CONTENT_ACCEPT_JSON,
        auth: INTERNO_AUTH
   };
   
    axios.request(options).then(function (response) {
        res.json(response.data);
    }).catch(function (error) {
        console.error(error);
    });
});