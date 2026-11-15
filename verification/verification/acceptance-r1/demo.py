import logging,tempfile
from pathlib import Path
from signed_fixtures import generate
from test_contract import verify
from in_toto.exceptions import CoverageError
logging.disable(logging.CRITICAL)
print('Real Ed25519 signatures; offline inspection runner')
with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
    directory=Path(directory)
    meta,keys,links=generate(directory/'valid')
    report,calls=verify(meta,keys,links,directory/'valid')
    print('Strict coverage:',report.ok,'records=',len(report.records),'runner=',calls)
    row=report.records_for('package','materials')[0]
    print('MATCH:',row.artifact,'->',row.dest_item+':'+row.dest_artifact)
    print('Rule index:',row.rule_index,'binding:',row.binding,'digests equal:',row.source_hashes==row.dest_hashes)
    allow=report.records_for('compile','materials')[0]
    print('ALLOW binding:',allow.binding,'source_hashes:',allow.source_hashes)
    for name,kwargs in [('Uncovered',{'uncovered':True}),('Digest mismatch',{'mismatch':True})]:
        folder=directory/name.replace(' ','-');meta,keys,links=generate(folder,**kwargs)
        try:verify(meta,keys,links,folder)
        except CoverageError:print(name+': rejected; no partial success returned')
        else:raise AssertionError('unexpected success')
print('Inspection command never spawned; live verification completed.')
