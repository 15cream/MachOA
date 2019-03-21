import ConfigParser

config = ConfigParser.RawConfigParser()

config.add_section('PATH')
config.set('PATH', 'binary', '../samples/')
config.set('PATH', 'dds', '../dds/')
config.set('PATH', 'xmls', '../xmls/')
config.set('PATH', 'dbs', '../dbs/')


# Writing our configuration file to 'example.etree'
with open('/home/gjy/Desktop/MachOA/config/config', 'wb') as configfile:
    config.write(configfile)