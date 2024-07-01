// defining the server port
const port = 8000;

// initializing installed dependencies
const express = require("express");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
require("dotenv").config();
const axios = require("axios");
const app = express();
const cors = require("cors");
const env = process.env.NODE_ENV;

const limiter = rateLimit({
  windowMs: 0.5 * 60 * 1000, // 30 seconds
  max: 5, // limit each IP to 5 requests per windowMs
});

const allowedOrigins = ['https://qamiespaciosky.sky.com.mx', 'https://miespaciosky.sky.com.mx'];
if ("development" === env) { // local development purposes
  allowedOrigins.push('https://localhost:3000');
}

// X-Rate-Limiting
app.use(limiter);
// CORS
app.use(cors({
  origin:allowedOrigins,
  credentials: true,
  methods: ['POST', 'GET', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
// HSTS
app.use(helmet());
app.use(
  helmet.hsts({
    maxAge: 300,
    includeSubDomains: true,
    preload: true,
  })
);

const {
  REACT_APP_URL_OSB,
  REACT_APP_USERNAME_OSB,
  REACT_APP_PASSWORD_OSB,
  REACT_APP_URL_INTERNO,
  REACT_APP_USER_INTERNO,
  REACT_APP_PASSWORD_INTERNO,
} = process.env;

const CONTENT_ACCEPT_JSON = {
  "Content-type": "application/json",
  Accept: "application/json",
};

const OSB_AUTH = {
  username: REACT_APP_USERNAME_OSB ?? "",
  password: REACT_APP_PASSWORD_OSB ?? "",
};

const INTERNO_AUTH = {
  username: REACT_APP_USER_INTERNO ?? "",
  password: REACT_APP_PASSWORD_INTERNO ?? "",
};

// listening for port
app.listen(port, () => console.log(`Server is running on ${port}`));

app.get("/", (req, rest) => {
  return "hello world";
});

// API request
app.post("/EnterpriseServices/Sel/Solicitud/generarQueja", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_OSB + "/EnterpriseServices/Sel/Solicitud/generarQueja",
    data: req,
    headers: CONTENT_ACCEPT_JSON,
    auth: OSB_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      console.error(error);
    });
});

app.post("/EnterpriseServices/Sel/Solicitud/crearSugerencia", (req, res) => {
  const options = {
    method: "POST",
    url:
      REACT_APP_URL_OSB + "/EnterpriseServices/Sel/Solicitud/crearSugerencia",
    data: req,
    headers: CONTENT_ACCEPT_JSON,
    auth: OSB_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      console.error(error);
    });
});

app.post(
  "/EnterpriseServices/Sel/Solicitud/Solicitud/responderEncuesta",
  (req, res) => {
    const options = {
      method: "POST",
      url:
        REACT_APP_URL_OSB +
        "/EnterpriseServices/Sel/Solicitud/responderEncuesta",
      data: req,
      headers: CONTENT_ACCEPT_JSON,
      auth: OSB_AUTH,
    };

    axios
      .request(options)
      .then(function (response) {
        res.json(response.data);
      })
      .catch(function (error) {
        console.error(error);
      });
  }
);

app.post(
  "/EnterpriseServices/Sel/AltaSolicitudDeServicioRest",
  (req, res) => {
    const options = {
      method: "POST",
      url:
        REACT_APP_URL_OSB +
        "/EnterpriseServices/Sel/AltaSolicitudDeServicioRest",
      data: req,
      headers: CONTENT_ACCEPT_JSON,
      auth: OSB_AUTH,
    };

    axios
      .request(options)
      .then(function (response) {
        res.json(response.data);
      })
      .catch(function (error) {
        console.error(error);
      });
  }
);

app.post("/EnterpriseFlows/Sel/AutenticarUsuarioRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseFlows/Sel/AutenticarUsuarioRest",
    data: req,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      console.error(error);
    });
});

app.post("/EnterpriseServices/Sel/ConsultaConsumoDatosRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaConsumoDatosRest",
    data: req,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      console.error(error);
    });
});

app.post("/EnterpriseServices/Sel/ConsultaDatosGeneralesRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaDatosGeneralesRest",
    data: req,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      console.error(error);
    });
});

app.post("/EnterpriseServices/Sel/ConsultaPaqAdicionalDatosRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaPaqAdicionalDatosRest",
    data: req,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      console.error(error);
    });
});

app.post("/EnterpriseServices/Sel/ConsultaParrillaGuiaSkyRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaParrillaGuiaSkyRest",
    data: req,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      console.error(error);
    });
});

app.post("/EnterpriseServices/Sel/ConsultaSolicitudDeServicioRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaSolicitudDeServicioRest",
    data: req,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      console.error(error);
    });
});

app.post("/EnterpriseServices/Sel/GestionarSSComprarServiciosRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/GestionarSSComprarServiciosRest",
    data: req,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      console.error(error);
    });
});

app.post("/EnterpriseFlows/Sel/ModificarPasswordRegistroRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseFlows/Sel/ModificarPasswordRegistroRest",
    data: req,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      console.error(error);
    });
});

app.post("/EnterpriseServices/Sel/ReEnviarEmailPreRegSelEBSRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ReEnviarEmailPreRegSelEBSRest",
    data: req,
    headers: CONTENT_ACCEPT_JSON,
    auth: INTERNO_AUTH,
  };

  axios
    .request(options)
    .then(function (response) {
      res.json(response.data);
    })
    .catch(function (error) {
      console.error(error);
    });
});