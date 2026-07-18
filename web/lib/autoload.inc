<?php

$mrbs_composer_autoload = __DIR__ . '/../../vendor/autoload.php';

if (is_readable($mrbs_composer_autoload))
{
  require $mrbs_composer_autoload;
}

unset($mrbs_composer_autoload);

spl_autoload_register(function ($class) {

  $base_dir = __DIR__ . '/';

  // Replace namespace separators with directory separators.
  // Append '.php'
  $file = str_replace('\\', '/', $class) . '.php';

  $file = $base_dir . $file;
  if (is_readable($file))
  {
    require $file;
  }
});
