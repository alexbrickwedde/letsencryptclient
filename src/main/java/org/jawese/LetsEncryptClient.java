package org.jawese;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

public class LetsEncryptClient {
    // RSA key size of generated key pairs
    private static final int KEY_SIZE = 2048;

    private File keystorefile = null;
    private String keystorepass = "";
    private File userkey = null;

    private static HashMap<String, String> challengeList = new HashMap<>();

    public LetsEncryptClient(File keystorefile, String keystorepass, File userkey) {
        this.keystorefile = keystorefile;
        this.keystorepass = keystorepass;
        this.userkey = userkey;
    }

    /**
     * Generates a certificate for the given domains. Also takes care for the
     * registration process.
     *
     * @param domains Domains to get a common certificate for
     */
    public void fetchCertificate(Collection<String> domains) throws IOException, AcmeException {
        // Load the user key file. If there is no key file, create a new one.
        KeyPair userKeyPair = loadOrCreateUserKeyPair();

        // Create a session for Let's Encrypt.
        // Use "acme://letsencrypt.org" for production server
        Session session = new Session("acme://letsencrypt.org/");

        // Get the Account.
        // If there is no account yet, create a new one.
        Account acct = findOrRegisterAccount(session, userKeyPair);

        // Load or create a key pair for the domains. This should not be the
        // userKeyPair!
        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);

        // Order the certificate
        Order order = acct.newOrder().domains(domains).create();

        // Perform all required authorizations
        for (Authorization auth : order.getAuthorizations()) {
            authorize(auth);
        }

        // Generate a CSR for all of the domains, and sign it with the domain key pair.
        CSRBuilder csrb = new CSRBuilder();
        csrb.addDomains(domains);
        csrb.sign(domainKeyPair);

        // Order the certificate
        order.execute(csrb.getEncoded());

        // Wait for the order to complete
        try {
            int attempts = 10;
            while (order.getStatus() != Status.VALID && attempts-- > 0) {
                // Did the order fail?
                if (order.getStatus() == Status.INVALID) {
                    throw new AcmeException("Order failed... Giving up.");
                }

                // Wait for a few seconds
                Thread.sleep(3000L);

                // Then update the status
                order.update();
            }
        } catch (InterruptedException ex) {
            System.err.println("interrupted" + ex.getLocalizedMessage());
            Thread.currentThread().interrupt();
        }

        // Get the certificate
        Certificate certificate = order.getCertificate();

        System.out.println("Success! The certificate for domains has been generated!");

        List<X509Certificate> certificateChain = certificate.getCertificateChain();
        try {
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(null);
            PrivateKey key = domainKeyPair.getPrivate();
            keystore.setKeyEntry("key-alias", key, this.keystorepass.toCharArray(),
                    certificateChain.toArray(new java.security.cert.Certificate[certificateChain.size()]));
            keystore.store(new FileOutputStream(this.keystorefile),
                    this.keystorepass.toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Loads a user key pair from {@value #USER_KEY_FILE}. If the file does not
     * exist, a new key pair is generated and saved.
     * <p>
     * Keep this key pair in a safe place! In a production environment, you will not
     * be able to access your account again if you should lose the key pair.
     *
     * @return User's {@link KeyPair}.
     */
    private KeyPair loadOrCreateUserKeyPair() throws IOException {
        if (this.userkey.exists()) {
            // If there is a key file, read it
            try (FileReader fr = new FileReader(this.userkey)) {
                return KeyPairUtils.readKeyPair(fr);
            }

        } else {
            // If there is none, create a new key pair and save it
            KeyPair userKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
            try (FileWriter fw = new FileWriter(this.userkey)) {
                KeyPairUtils.writeKeyPair(userKeyPair, fw);
            }
            return userKeyPair;
        }
    }

    /**
     * Finds your {@link Account} at the ACME server. It will be found by your
     * user's public key. If your key is not known to the server yet, a new account
     * will be created.
     * <p>
     * This is a simple way of finding your {@link Account}. A better way is to get
     * the URL and KeyIdentifier of your new account with
     * {@link Account#getLocation()} {@link Session#getKeyIdentifier()} and store it
     * somewhere. If you need to get access to your account later, reconnect to it
     * via {@link Account#bind(Session, URI)} by using the stored location.
     *
     * @param session {@link Session} to bind with
     * @return {@link Login} that is connected to your account
     */
    private Account findOrRegisterAccount(Session session, KeyPair accountKey) throws AcmeException {
        // Ask the user to accept the TOS, if server provides us with a link.
        URI tos = session.getMetadata().getTermsOfService();
        if (tos != null) {
            // acceptAgreement(tos);
        }

        Account account = new AccountBuilder().agreeToTermsOfService().useKeyPair(accountKey).create(session);
        System.out.println("Registered a new user, URL: " + account.getLocation());

        return account;
    }

    /**
     * Authorize a domain. It will be associated with your account, so you will be
     * able to retrieve a signed certificate for the domain later.
     *
     * @param auth {@link Authorization} to perform
     */
    private void authorize(Authorization auth) throws AcmeException {
        System.out.println("Authorization for domain " + auth.getIdentifier().getDomain());

        // The authorization is already valid. No need to process a challenge.
        if (auth.getStatus() == Status.VALID) {
            return;
        }

        // Find the desired challenge and prepare it.
        Challenge challenge = httpChallenge(auth);
        if (challenge == null) {
            throw new AcmeException("No challenge found");
        }

        // If the challenge is already verified, there's no need to execute it again.
        if (challenge.getStatus() == Status.VALID) {
            return;
        }

        // Now trigger the challenge.
        challenge.trigger();

        // Poll for the challenge to complete.
        try {
            int attempts = 10;
            while (challenge.getStatus() != Status.VALID && attempts-- > 0) {
                // Did the authorization fail?
                if (challenge.getStatus() == Status.INVALID) {
                    throw new AcmeException("Challenge failed... Giving up.");
                }

                // Wait for a few seconds
                Thread.sleep(3000L);

                // Then update the status
                challenge.update();
            }
        } catch (InterruptedException ex) {
            System.err.println("interrupted" + ex.getLocalizedMessage());
            Thread.currentThread().interrupt();
        }

        Http01Challenge authchallenge = auth.findChallenge(Http01Challenge.TYPE);

        challengeList.remove(authchallenge.getToken());

        // All reattempts are used up and there is still no valid authorization?
        if (challenge.getStatus() != Status.VALID) {
            throw new AcmeException(
                    "Failed to pass the challenge for domain " + auth.getIdentifier().getDomain() + ", ... Giving up.");
        }
    }

    /**
     * Prepares a HTTP challenge.
     * <p>
     * The verification of this challenge expects a file with a certain content to
     * be reachable at a given path under the domain to be tested.
     * <p>
     * This example outputs instructions that need to be executed manually. In a
     * production environment, you would rather generate this file automatically, or
     * maybe use a servlet that returns {@link Http01Challenge#getAuthorization()}.
     *
     * @param auth {@link Authorization} to find the challenge in
     * @return {@link Challenge} to verify
     */
    public Challenge httpChallenge(Authorization auth) throws AcmeException {
        // Find a single http-01 challenge
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
        if (challenge == null) {
            throw new AcmeException("Found no " + Http01Challenge.TYPE + " challenge, don't know what to do...");
        }

        challengeList.put(challenge.getToken(), challenge.getAuthorization());
        return challenge;
    }

    public static String getChallengeContent(String token) {
        try {
            return challengeList.get(token);
        } catch (Exception e) {
        }
        return null;
    }
}
