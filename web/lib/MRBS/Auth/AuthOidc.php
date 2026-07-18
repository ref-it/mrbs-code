<?php
declare(strict_types=1);
namespace MRBS\Auth;

use MRBS\User;


/**
 * Authentication management scheme that delegates everything to an OpenID Connect (OIDC)
 * Identity Provider.  You should use this scheme, along with the session scheme with the
 * same name, if you want your users to authenticate using OIDC Single Sign-on.
 *
 * See the session management scheme with the same name for information on how to configure
 * OIDC authentication.  This authentication module on its own doesn't work.
 */
class AuthOidc extends Auth
{
  public function __construct()
  {
    $this->checkSessionMatchesType();
  }


  public function validateUser(
    #[\SensitiveParameter]
    ?string $user,
    #[\SensitiveParameter]
    ?string $pass)
  {
    $current_username = \MRBS\session()->getUsername();

    if (isset($current_username) && $current_username === $user)
    {
      return $user;
    }

    return false;
  }


  public function getUserFresh(string $username) : ?User
  {
    $user = new User($username);
    $user->level = $this->getLevel($username);
    $user->email = $this->getEmail($username);
    $user->display_name = $this->getUserDisplayName($username);

    return $user;
  }


  /**
   * Determines the user's access level.
   *
   * It does this by comparing OIDC claims with $auth['oidc']['admin'] and, if configured,
   * $auth['oidc']['user'].  If any claim value matches an admin value, the user is
   * considered an admin and the maximum level is returned.  If $auth['oidc']['user'] is
   * configured and no claim value matches, the user is level 0 even though they are
   * logged in - this allows OIDC to also be used as an access filter, eg by group
   * membership, rather than just as an identity provider.
   *
   * If the user is not logged in, or the provided username doesn't match our current OIDC
   * session, 0 is returned.
   */
  private function getLevel(string $username) : int
  {
    global $auth, $max_level;

    if (!isset($auth['oidc']['admin']))
    {
      return $this->getDefaultLevel($username);
    }

    $current_username = \MRBS\session()->getUsername();

    if (!isset($current_username) || ($current_username !== $username))
    {
      return 0;
    }

    $claims = \MRBS\session()->getClaims();

    if (!isset($claims))
    {
      return 0;
    }

    foreach ($auth['oidc']['admin'] as $claim => $values)
    {
      if (self::claimMatches($claims, $claim, $values))
      {
        return $max_level;
      }
    }

    if (isset($auth['oidc']['user']))
    {
      foreach ($auth['oidc']['user'] as $claim => $values)
      {
        if (self::claimMatches($claims, $claim, $values))
        {
          return 1;
        }
      }
      return 0;
    }

    return 1;
  }


  // Checks whether any of $values is present in the (scalar or array) claim $claim
  // in the OIDC claims object $claims.
  private static function claimMatches(object $claims, string $claim, array $values) : bool
  {
    if (!property_exists($claims, $claim))
    {
      return false;
    }

    $actual_values = $claims->$claim;

    if (!is_array($actual_values))
    {
      $actual_values = array($actual_values);
    }

    return (count(array_intersect($values, $actual_values)) > 0);
  }


  // Gets the user's e-mail address from the OIDC claims.
  // Returns an empty string if no e-mail address claim was found.
  private function getEmail(string $username) : string
  {
    global $auth;

    $current_username = \MRBS\session()->getUsername();

    if (!isset($current_username) || ($current_username !== $username))
    {
      return '';
    }

    $claims = \MRBS\session()->getClaims();
    $email_claim = $auth['oidc']['claims']['email'] ?? 'email';

    return (isset($claims) && property_exists($claims, $email_claim)) ? $claims->$email_claim : '';
  }


  // Gets the user's display name from the OIDC claims.
  // Falls back to the given_name/family_name claims, and then to the username,
  // if the configured 'name' claim isn't present.
  private function getUserDisplayName(string $username) : string
  {
    global $auth;

    $current_username = \MRBS\session()->getUsername();

    if (!isset($current_username) || ($current_username !== $username))
    {
      return $username;
    }

    $claims = \MRBS\session()->getClaims();

    if (!isset($claims))
    {
      return $username;
    }

    $name_claim = $auth['oidc']['claims']['name'] ?? 'name';

    if (property_exists($claims, $name_claim) && ($claims->$name_claim !== ''))
    {
      return $claims->$name_claim;
    }

    $given_name = $claims->given_name ?? '';
    $family_name = $claims->family_name ?? '';
    $display_name = trim("$given_name $family_name");

    return ($display_name !== '') ? $display_name : $username;
  }

}
