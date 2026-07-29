<?php
declare(strict_types=1);
namespace MRBS;

require "defaultincludes.inc";

/**
 * Fixed OpenID Connect redirect_uri, registered as such with the Identity Provider.  The
 * Identity Provider redirects back here after login, and we then send the browser on to
 * whichever page originally triggered the login (see SessionOidc::authGet(), which stores
 * that page in the session before redirecting to the Identity Provider).
 */

$target_url = session()->get('oidc_target_url') ?? url_base();

if (method_exists(session(), 'authGet'))
{
  session()->authGet($target_url);
}
else
{
  location_header($target_url);
}
