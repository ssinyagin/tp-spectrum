push( @Torrus::DevDiscover::loadModules,
      'Torrus::DevDiscover::SpectrumDevices' );

# see IANAifType-MIB.my for values
$Torrus::DevDiscover::SpectrumDevices::onlyIfTypes{6} = 1;  # ethernetCsmacd(6)

# Default blacklist
$Torrus::DevDiscover::SpectrumDevices::excludeDevtypes{'MicrosoftWindows'} = 1;

1;
