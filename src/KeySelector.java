package id.kodekreatif.cordova;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;

import id.co.kodekreatif.pdfdigisign.*;

import java.security.cert.*;

import android.content.Context;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.ArrayList;

public class KeySelector extends CordovaPlugin implements KeyChainAliasCallback {

  private static final String TAG = KeySelector.class.getSimpleName();
  private static final int REQUEST = 1;
  private String trustedStore = "/etc/ssl/certs/java/cacerts";


  CallbackContext context = null;

  // http://stackoverflow.com/a/9855338
  private static String bytesToHex(byte[] bytes) {
    final char[] hexArray = "0123456789ABCDEF".toCharArray();
    char[] hexChars = new char[bytes.length * 2];
    for ( int j = 0; j < bytes.length; j++ ) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }


  @Override
  public boolean execute(String action, JSONArray data, CallbackContext callbackContext) throws JSONException {
    if (action.equals("select")) {
      KeyChain.choosePrivateKeyAlias(cordova.getActivity(), this, new String[] { "RSA" }, null, null, -1, null); 
      context = callbackContext;

      return true;
    } else {

      return false;

    }
  }

  @Override
  public void alias(final String alias) {
    ArrayList<CertInfo> certs = new ArrayList<CertInfo>();
    if (context != null) {
      Context thisContext=this.cordova.getActivity().getApplicationContext();
      try {
        X509Certificate[] chain = KeyChain.getCertificateChain(thisContext, alias);
        
        boolean ok = true;
        for (X509Certificate x509: chain) {
          CertInfo certInfo = new CertInfo();

          certInfo.serialNumber = x509.getSerialNumber().toString();
          certInfo.signature = bytesToHex(x509.getSignature());
          certInfo.issuer = x509.getIssuerX500Principal().toString();
          certInfo.subject = x509.getSubjectX500Principal().toString();
          try {
            if (certInfo.issuer.equals(certInfo.subject)) {
              certInfo.selfSigned = true;
            } else {
              certInfo.selfSigned = false;
            }

            certInfo = Verificator.checkRevocation(x509, x509, certInfo);
            certInfo.verified = true;
          } catch (Exception e) {
            certInfo.verified = false;
            certInfo.problems.add(e.getMessage());
            ok = false;
          }

          certInfo.notBefore = x509.getNotBefore();
          certInfo.notAfter = x509.getNotAfter();

          try {
            x509.checkValidity();
            certInfo.valid = true;
          } catch (CertificateExpiredException e) {
            certInfo.valid = false;
            certInfo.problems.add("expired");
            ok = false;
          } catch (CertificateNotYetValidException e) {
            certInfo.valid = false;
            certInfo.problems.add("not-yet-valid");
            ok = false;
          }
          certs.add(certInfo);
        }
        Gson gson = new GsonBuilder().create();
        String s = gson.toJson(certs);

        if (ok) {
          context.success("{\"alias\": \"" + alias + "\", \"certs\": "+ s +"}");    
        } else {
          context.success("{\"alias\": \"\", \"certs\": "+ s +"}");    
        }
      } catch(Exception e) {
        context.success("{\"alias\":null, \"error\": \"" + e.getMessage() + "\"}");    
      }
    } else {
      Log.d(TAG, "context is null");
    }
  }
}
