import os
import os.path
import sys
from multiprocessing import Pool

def main():
    sigmaDir = sys.argv[ 1 ]
    rootOutputDir = sys.argv[ 2 ]

    with Pool( 16 ) as pool:
        os.system( 'mkdir ./lc-rules' )
        for d in ( 'windows/builtin',
                   'windows/process_creation',
                   'windows/sysmon', ):
            outDir = d.replace( '/', '_' )
            print( "Creating dir: %s" % ( outDir, ) )
            os.system( 'mkdir -p %s%s' % ( rootOutputDir, outDir, ) )
            for r, _, files in os.walk( '%srules/%s/' % ( sigmaDir, d, ) ):
                for f in files:
                    thisFile = os.path.join( r, f )
                    if not os.path.isfile( thisFile ):
                        print( "Not file: %s" % ( thisFile, ) )
                        continue
                    print( "Process rule %s" % ( thisFile, ) )
                    outFile = "%s%s/%s" % ( rootOutputDir, outDir, f )
                    pool.apply_async( processRule, ( sigmaDir, thisFile, outFile ) )
        pool.close()
        pool.join()

def processRule( sigmaDir, thisFile, outFile ):
    # Artifact rules.
    os.system( "python3 %stools/sigmac -t limacharlie --backend-option lc_target=artifact -c %stools/config/limacharlie.yml %s > %s" % ( sigmaDir, sigmaDir, thisFile, outFile ) )
    if os.path.getsize( outFile ) == 0:
        print( "rule %s was empty, deleting" % ( outFile, ) )
        os.system( 'rm %s' % ( outFile, ) )

    # EDR rules.
    # If a rule file already exists with that name, use an alternate one.
    try:
        if os.path.getsize( outFile ) != 0:
            outFile = os.path.splitext( outFile )[ 0 ] + '-edr.yml'
            print( "artifact sourced rule exists, use alt-name: %s" % ( outFile, ) )
    except:
        pass
    os.system( "python3 %stools/sigmac -t limacharlie --backend-option lc_target=edr -c %stools/config/limacharlie.yml %s > %s" % ( sigmaDir, sigmaDir, thisFile, outFile ) )
    if os.path.getsize( outFile ) == 0:
        print( "rule %s was empty, deleting" % ( outFile, ) )
        os.system( 'rm %s' % ( outFile, ) )

if __name__ == "__main__":
    main()