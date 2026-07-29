<?php
declare(strict_types=1);
namespace MRBS\Session;

use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use MRBS\Form\Form;
use MRBS\User;
use function MRBS\auth;
use function MRBS\location_header;
use function MRBS\remove_query_parameter;
use function MRBS\this_page;
use function MRBS\url_base;


/**
 * Session management scheme that delegates everything to an OpenID Connect (OIDC) Identity
 * Provider.  You should use this scheme, along with the authentication scheme with the same
 * name, if you want your users to authenticate using OIDC Single Sign-on.
 *
 * In config.inc.php:
 *
 *     $auth['type'] = 'oidc';
 *     $auth['session'] = 'oidc';
 *     $auth['oidc']['provider_url'] = 'https://idp.example.com/realms/example';
 *     $auth['oidc']['client_id'] = 'mrbs';
 *     $auth['oidc']['client_secret'] = '...';
 *     $auth['oidc']['claims']['username'] = 'preferred_username';
 *     $auth['oidc']['admin']['groups'] = ['mrbs-admins'];
 *
 * This scheme assumes that you've already registered MRBS as a client (relying party) with
 * your Identity Provider.  The redirect URI to register is the fixed URL of oidc_callback.php
 * (eg "https://example.com/mrbs/oidc_callback.php") - the Identity Provider always redirects
 * back there, regardless of which page a user first visited, and oidc_callback.php then sends
 * the browser on to that original page.
 *
 * See the AUTHENTICATION file for more information.
 */
class SessionOidc extends SessionWithLogin
{
  private $client;


  public function __construct()
  {
    global $auth;

    $this->checkTypeMatchesSession();

    if (!isset($auth['oidc']['provider_url']))
    {
      throw new \Exception('$auth["oidc"]["provider_url"] must be set in the config file.');
    }

    if (!isset($auth['oidc']['client_id']))
    {
      throw new \Exception('$auth["oidc"]["client_id"] must be set in the config file.');
    }

    $this->client = new OpenIDConnectClient(
      $auth['oidc']['provider_url'],
      $auth['oidc']['client_id'],
      $auth['oidc']['client_secret'] ?? null
    );

    // Always come back to the same, fixed callback page, rather than the jumbojett
    // library's default of the current page, so that only one redirect URI needs to
    // be registered with the Identity Provider.
    $this->client->setRedirectURL(url_base() . 'oidc_callback.php');

    if (!empty($auth['oidc']['scopes']))
    {
      $this->client->addScope($auth['oidc']['scopes']);
    }

    if (!empty($auth['oidc']['code_challenge_method']))
    {
      $this->client->setCodeChallengeMethod($auth['oidc']['code_challenge_method']);
    }

    $this->client->setVerifyPeer($auth['oidc']['verify_peer'] ?? true);
    $this->client->setVerifyHost($auth['oidc']['verify_peer'] ?? true);

    if (!empty($auth['oidc']['ca_cert_path']))
    {
      $this->client->setCertPath($auth['oidc']['ca_cert_path']);
    }

    $this->samesite = self::SAMESITE_LAX;
    parent::__construct();
  }


  // No need to prompt for a name - the user is redirected to the Identity Provider.
  public function authGet(?string $target_url=null, ?string $returl=null, ?string $error=null, bool $raw=false) : void
  {
    global $auth;

    if (!isset($target_url))
    {
      $target_url = $this->form['target_url'] ?? this_page(true);
    }

    // Remember which page to return to once oidc_callback.php hears back from the
    // Identity Provider (see the class doc comment above).
    $this->set('oidc_target_url', $target_url);

    try
    {
      $authenticated = $this->client->authenticate();
    }
    catch (OpenIDConnectClientException $e)
    {
      // Fall back to the standard login form, showing the error, exactly as
      // SessionWithLogin::getValidUser() does for a failed username/password.
      parent::authGet($target_url, $returl, $e->getMessage(), true);
      return;
    }

    if (!$authenticated)
    {
      // $this->client->authenticate() will normally already have redirected to the
      // Identity Provider and exited.  This is just a safety net.
      return;
    }

    // We're back from the Identity Provider and the ID token has been validated.
    $claims = $this->client->getVerifiedClaims();
    $username_claim = $auth['oidc']['claims']['username'] ?? 'preferred_username';
    $username = $claims->$username_claim ?? $claims->sub;

    $this->set('oidc_claims', $claims);
    $this->set('oidc_username', $username);
    $this->set('oidc_id_token', $this->client->getIdToken());

    // Strip the authorization code/state from the URL we land on.
    $clean_target_url = remove_query_parameter($target_url, 'code');
    $clean_target_url = remove_query_parameter($clean_target_url, 'state');

    if (!empty($returl))
    {
      $clean_target_url .= (mb_strpos($clean_target_url, '?') === false) ? '?' : '&';
      $clean_target_url .= 'returl=' . urlencode($returl);
    }

    location_header($clean_target_url);
  }


  public function getCurrentUser() : ?User
  {
    $username = $this->getUsername();

    return (isset($username)) ? auth()->getUser($username) : parent::getCurrentUser();
  }


  public function getUsername() : ?string
  {
    return $this->get('oidc_username');
  }


  // Returns the verified ID token claims from the current OIDC session, or null if the
  // user isn't logged in via OIDC.
  public function getClaims() : ?object
  {
    return $this->get('oidc_claims');
  }


  public function getLogonFormParams() : ?array
  {
    $target_url = this_page(true);

    return array(
        'action' => $target_url,
        'method' => Form::METHOD_POST,
        'hidden_inputs' =>  array('target_url' => $target_url,
                                  'action'     => 'QueryName')
      );
  }


  public function processForm() : void
  {
    if (isset($this->form['action']))
    {
      if ($this->form['action'] == 'QueryName')
      {
        $this->authGet($this->form['target_url']);
        exit(); // unnecessary because authGet() exits, but just included for clarity
      }

      if ($this->form['action'] == 'SetName')
      {
        // If we're going to do something then check the CSRF token first
        Form::checkToken();

        // You should only get here after clicking the logoff link, no matter what
        // the value of the other form parameters.
        $this->logoffUser();

        location_header($this->form['target_url']); // Redirect browser to initial page
      }
    }
  }


  public function logoffUser(?string $redirect_url=null) : void
  {
    global $auth;

    $id_token = $this->get('oidc_id_token');

    $this->unset('oidc_claims');
    $this->unset('oidc_username');
    $this->unset('oidc_id_token');

    if (!empty($auth['oidc']['end_session_enabled']) && isset($id_token))
    {
      try
      {
        // signOut() redirects to the Identity Provider's end-session endpoint and exits.
        $this->client->signOut($id_token, $redirect_url ?? url_base());
      }
      catch (OpenIDConnectClientException $e)
      {
        // The provider doesn't support RP-initiated logout (no end_session_endpoint in
        // its discovery document) - fall through to a purely local logoff.
      }
    }

    parent::logoffUser($redirect_url);
  }

}
