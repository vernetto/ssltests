Se ti vedi sun.security.ssl.ServerHandshaker linea 436/504, sarebbe semplice fare una patch per identificare questa issue con un flag:

 

ti faccio notare anche come i messaggi del Debug siano totalmente fuorvianti…

 

   else if ((!this.isInitialHandshake) && (this.secureRenegotiation))

    {

      fatalSE((byte)40, "Inconsistent secure renegotiation indication");

    }

    if ((i == 0) || (!this.secureRenegotiation)) {

      if (this.isInitialHandshake)

      {

        if (!allowLegacyHelloMessages) {

          fatalSE((byte)40, "Failed to negotiate the use of secure renegotiation");

        }

        if ((debug != null) && (Debug.isOn("handshake"))) {

          System.out.println("Warning: No renegotiation indication in ClientHello, allow legacy ClientHello");

        }

      }

**      else if (!allowUnsafeRenegotiation)

      {

        if (this.activeProtocolVersion.v >= ProtocolVersion.TLS10.v)

        {

          warningSE((byte)100);

         

 

 

          this.invalidated = true;

          if (this.input.available() > 0) {

            fatalSE((byte)10, "ClientHello followed by an unexpected  handshake message");

          }

          return;

        }

**        fatalSE((byte)40, "Renegotiation is not allowed");

      }

      else if ((debug != null) && (Debug.isOn("handshake")))

      {

        System.out.println("Warning: continue with insecure renegotiation");

      }

    }

<pre>
    if (useExtendedMasterSecret)

    {

      localObject1 = (ExtendedMasterSecretExtension)paramClientHello.extensions.get(ExtensionType.EXT_EXTENDED_MASTER_SECRET);

      if (localObject1 != null) {

        this.requestedToUseEMS = true;

      } else if ((paramClientHello.protocolVersion.v >= ProtocolVersion.TLS10.v) &&

        (!allowLegacyMasterSecret)) {

        fatalSE((byte)40, "Extended Master Secret extension is required");

      }

    }
</pre>    
    

La cosa bella é che neanche ti dicono se un client non manda un certificate: e scrivilo un cacchio di log, una linea del tipo

“Request received from {IP Address} was rejected because it did not provide a client certificate”

Oppure

“Reqest received from {IP Address} was rejected because it attempted an unsecure  renegotiation without Extended MasterSecret”

 

Salverebbe il mondo una classettina simile con 10 righe su come installarla ed attivarla (via System Property) per JAP9, JAP7 e JAP8
