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
  max: 30, // limit each IP to 5 requests per windowMs
  keyGenerator: (req, res) => {
    return req.ip.replace(/:\d+[^:]*$/, '') // IP address from requestIp.mw(), as opposed to req.ip
  }
});

const allowedOrigins = ['https://qamiespaciosky.sky.com.mx', 'https://miespaciosky.sky.com.mx', 'https://misky.sky.com.mx'];
if ("development" === env) { // local development purposes
  allowedOrigins.push('https://localhost:3000');
}

// X-Rate-Limiting
app.set('trust proxy', 1)
app.use(limiter);
// CORS
app.use(cors({
  origin:allowedOrigins,
  credentials: true,
  methods: ['POST', 'GET', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Acceptcrc']
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
  REACT_APP_URL_INTERNO,
  REACT_APP_USER_INTERNO,
  REACT_APP_PASSWORD_INTERNO,
  REACT_APP_GOOGLE_API_KEY,
  REACT_APP_RECAPTCHA_KEY
} = process.env;

const CONTENT_ACCEPT_JSON = {
  "Content-type": "application/json",
  Accept: "application/json",
};

const OSB_AUTH = {
  username: REACT_APP_USER_INTERNO ?? "",
  password: REACT_APP_PASSWORD_INTERNO ?? "",
};

const INTERNO_AUTH = {
  username: REACT_APP_USER_INTERNO ?? "",
  password: REACT_APP_PASSWORD_INTERNO ?? "",
};

// listening for port
app.listen(process.env.PORT, '0.0.0.0', () => console.log(`Server is running on ${process.env.PORT}`));

app.get("/", (req, res) => {
  res.json({ message: "Welcome !!!!" });
});

// API request
app.post("/mi-sky-api/EnterpriseServices/Sel/Solicitud/generarQueja", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/Solicitud/generarQueja",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/Solicitud/crearSugerencia", (req, res) => {
  const options = {
    method: "POST",
    url:
      REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/Solicitud/crearSugerencia",
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
        REACT_APP_URL_INTERNO +
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
        REACT_APP_URL_INTERNO +
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

app.post("/mi-sky-api/EnterpriseFlows/Sel/AutenticarUsuarioRest", (req, res) => {
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaConsumoDatosRest", (req, res) => {
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaDatosGeneralesRest", (req, res) => {
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaPaqAdicionalDatosRest", (req, res) => {
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaParrillaGuiaSkyRest", (req, res) => {
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



app.post("/mi-sky-api/EnterpriseServices/Sel/GestionarSSComprarServiciosRest", (req, res) => {
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

app.post("/mi-sky-api/EnterpriseFlows/Sel/ModificarPasswordRegistroRest", (req, res) => {
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ReEnviarEmailPreRegSelEBSRest", (req, res) => {
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaPagosPorEventoRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaPagosPorEventoRest",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaPrecioRecargaRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaPrecioRecargaRest",
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

app.post("/mi-sky-api/EnterpriseServices/Siebel/Cuenta/consultarCuentaAsociada", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/Cuenta/consultarCuentaAsociada",
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

app.post("/mi-sky-api/EnterpriseServices/Siebel/Cuenta/consultarCuentaEspecial", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/Cuenta/consultarCuentaEspecial",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/Cuenta/consultarDatosUsuario", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/Cuenta/consultarDatosUsuario",
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

app.post("/mi-sky-api/EnterpriseServices/Brm/Factura/consultarEstadoCuenta", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Brm/Factura/consultarEstadoCuenta",
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

app.post("/mi-sky-api/EnterpriseServices/Brm/Factura/consultarFactura", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Brm/Factura/consultarFactura",
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

app.post("/mi-sky-api/EnterpriseServices/Brm/Factura/consultarFacturaPeriodo", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Brm/Factura/consultarFacturaPeriodo",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/Cuenta/consultarLDAP", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/Cuenta/consultarLDAP",
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

app.post("/mi-sky-api/EnterpriseServices/Siebel/Pago/consultarPago", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/Pago/consultarPago",
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

app.post("/mi-sky-api/EnterpriseServices/Siebel/PagoEvento/consultarProducto", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/PagoEvento/consultarProducto",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarRegimenFiscalRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarRegimenFiscalRest",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarServiciosAdicionalesRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarServiciosAdicionalesRest",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarUsoCFDIRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarUsoCFDIRest",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaSolicitudDeServicioRest", (req, res) => {
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

app.post("/mi-sky-api/EnterpriseServices/Sel/Solicitud/crearSolicitud", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/Solicitud/crearSolicitud",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/EjecutarRemoteBookingRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/EjecutarRemoteBookingRest",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/RegistrarDatosFiscalesRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/RegistrarDatosFiscalesRest",
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

app.post("/mi-sky-api/EnterpriseServices/Brm/Factura/obtenerFactura", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Brm/Factura/obtenerFactura",
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

app.post("/mi-sky-api/EnterpriseServices/Okta/Usuario/restablecerContrasena", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Okta/Usuario/restablecerContrasena",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaCuentaRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaCuentaRest",
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

app.post("/mi-sky-api/SbConsultaHorariosPagoPorEventoSelEBS/ConsultaHorariosPagoPorEventoRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/SbConsultaHorariosPagoPorEventoSelEBS/ConsultaHorariosPagoPorEventoRest",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ActivacionBlueToGoRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ActivacionBlueToGoRest",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ActualizaDatosFiscalesEBFRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ActualizaDatosFiscalesEBFRest",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaCanalGuiaSkyRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaCanalGuiaSkyRest",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultaControlRemotoRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultaControlRemotoRest",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarDatosFiscalesRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarDatosFiscalesRest",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarEstadosDeCuentaRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarEstadosDeCuentaRest",
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

app.post("/mi-sky-api/EnterpriseServices/Siebel/Cuenta/consultarFacturaCorporativo", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/Cuenta/consultarFacturaCorporativo",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/PagoEvento/consultarPPV", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/PagoEvento/consultarPPV",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarSaldosCorrientesRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarSaldosCorrientesRest",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ConsultarServiciosCuentaRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ConsultarServiciosCuentaRest",
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

app.post("/mi-sky-api/EnterpriseServices/Siebel/Equipo/consultarTICorporativo", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/Equipo/consultarTICorporativo",
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


app.post("/mi-sky-api/EnterpriseServices/Sel/Solicitud/enviarEmail", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/Solicitud/enviarEmail",
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


app.post("/mi-sky-api/EnterpriseServices/Sel/GestionarSSComprarDatosRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/GestionarSSComprarDatosRest",
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


app.post("/mi-sky-api/EnterpriseServices/Okta/Usuario/cambiarContrasena", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Okta/Usuario/cambiarContrasena",
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

app.post("/mi-sky-api/EnterpriseFlows/Sel/RecuperarPasswordUsrRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseFlows/Sel/RecuperarPasswordUsrRest",
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

app.post("/mi-sky-api/EnterpriseFlows/Sel/PreRegistroRest", (req, res) => {
  //ip from client
  const ip = req.ip || req.headers['x-forwarded-for'] || null

  // validate token
  const token = req.headers["acceptcrc"];

  const validateTokenData = `
    {
  "event": {
    "token": "${token}",
    "expectedAction": "USER_ACTION",
    "siteKey": "${REACT_APP_RECAPTCHA_KEY}"
  }
}
  ` 

  const validateTokenOptions = {
    method: "POST",
    url: "https://recaptchaenterprise.googleapis.com/v1/projects/sel-sky/assessments?key=" + REACT_APP_GOOGLE_API_KEY,
    data: validateTokenData,
    headers: CONTENT_ACCEPT_JSON
  };

  axios
    .request(validateTokenOptions)
    .then(function (response) {
      const data = response.data
      if(!data["tokenProperties"].valid) {
        console.log("captcha is invalid from IP: "+ip)
        return res.status(401).json({ msg: 'Unauthorized user' });
      } else { // call OSB
        const options = {
          method: "POST",
          url: REACT_APP_URL_INTERNO + "/EnterpriseFlows/Sel/PreRegistroRest",
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
      }
    })
    .catch(function (error) {
      console.log("it was not possible to validate the captcha from IP: "+ip)
      console.log(req.headers)
      console.log(req.headers.acceptcrc)
      return res.status(401).json({ msg: 'Unauthorized user' });
    });

});

app.post("/mi-sky-api/EnterpriseFlows/Sel/RegistrarQuejaRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseFlows/Sel/RegistrarQuejaRest",
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

app.post("/mi-sky-api/EnterpriseFlows/Sel/RegistrarSugerenciaRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseFlows/Sel/RegistrarSugerenciaRest",
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

app.post("/mi-sky-api/EnterpriseServices/Siebel/Equipo/consultarIRD", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Siebel/Equipo/consultarIRD",
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

app.post("/mi-sky-api/EnterpriseServices/Sel/ValidarPreRegistroRest", (req, res) => {
  const options = {
    method: "POST",
    url: REACT_APP_URL_INTERNO + "/EnterpriseServices/Sel/ValidarPreRegistroRest",
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