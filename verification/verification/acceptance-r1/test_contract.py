import dataclasses
import pytest
from securesystemslib.signer import CryptoSigner
from in_toto.models.metadata import Metablock
from in_toto.models.link import Link,FILENAME_FORMAT
from in_toto.verifylib import in_toto_verify,in_toto_verify_coverage,verify_item_rules_coverage
from in_toto.coverage import CoverageCollector
from in_toto.exceptions import CoverageError,ThresholdVerificationError
from signed_fixtures import generate,HASH

def resigner(metadata,links,directory):
    worker=CryptoSigner.generate_ed25519();owner=CryptoSigner.generate_ed25519()
    keyid=worker.public_key.keyid;public=worker.public_key.to_dict();public['keyid']=keyid
    metadata.signed.keys={keyid:public}
    for step in metadata.signed.steps:
        step.pubkeys=[keyid]
        signed=Metablock(signed=links[step.name]);signed.create_signature(worker)
        signed.dump(str(directory/FILENAME_FORMAT.format(step_name=step.name,keyid=keyid)))
    metadata.signatures=[];metadata.create_signature(owner)
    public=owner.public_key.to_dict();public['keyid']=owner.public_key.keyid
    return {owner.public_key.keyid:public},worker

def verify(metadata,keys,links,directory,strict=True,old=False):
    calls=[]
    def runner(name,*args,**kw):
        calls.append(name);return Metablock(signed=links[name])
    function=in_toto_verify if old else in_toto_verify_coverage
    kw={} if old else {'strict':strict}
    return function(metadata,keys,link_dir_path=str(directory),persist_inspection_links=False,inspection_runner=runner,**kw),calls

def test_signed_prefix_match_and_immutable_evidence(tmp_path):
    meta,keys,links=generate(tmp_path)
    report,calls=verify(meta,keys,links,tmp_path)
    assert report.ok and report.strict and calls==['audit']
    row=report.records_for('package','materials')[0]
    assert (row.artifact,row.rule_index,row.source_prefix,row.dest_prefix,row.dest_item,row.dest_artifact)==('stage/tool',0,'stage','build','compile','build/tool')
    assert row.binding=='hash' and dict(row.source_hashes)==dict(row.dest_hashes)==HASH
    with pytest.raises(dataclasses.FrozenInstanceError):row.rule_index=999
    with pytest.raises(TypeError):row.source_hashes[0]=('sha256','fake')
    allow=report.records_for('compile','materials')[0]
    assert allow.binding=='wildcard' and allow.source_hashes is None
    links['compile'].materials['src/code']['sha256']='99'*32
    assert dict(row.source_hashes)==HASH

def test_uncovered_rejects_before_inspection(tmp_path):
    meta,keys,links=generate(tmp_path,uncovered=True);calls=[]
    def runner(*args,**kw):calls.append(True);raise AssertionError('must not run')
    with pytest.raises(CoverageError):
        in_toto_verify_coverage(meta,keys,link_dir_path=str(tmp_path),persist_inspection_links=False,inspection_runner=runner)
    assert calls==[]

def test_non_strict_has_explicit_failed_coverage(tmp_path):
    meta,keys,links=generate(tmp_path,uncovered=True)
    report,calls=verify(meta,keys,links,tmp_path,strict=False)
    assert not report.ok and not report.strict and calls==['audit']
    assert [row.artifact for row in report.unconsumed]==['unexplained/file']

def test_one_of_multiple_digests_mismatch_never_consumes(tmp_path):
    meta,keys,links=generate(tmp_path,mismatch=True)
    with pytest.raises(CoverageError):verify(meta,keys,links,tmp_path)
    report,_=verify(meta,keys,links,tmp_path,strict=False)
    assert report.records_for('package','materials','match')==()
    trace=next(t for t in report.rule_trace if t.item_name=='package' and t.source_type=='materials')
    assert trace.consumed==() and trace.queue_after==('stage/tool',)

def test_rule_indices_preserve_non_consuming_duplicates(tmp_path):
    meta,keys,links=generate(tmp_path)
    rules=meta.signed.steps[1].expected_materials
    rules.insert(0,['MATCH','absent','WITH','PRODUCTS','FROM','compile'])
    rules.append(list(rules[1]));keys,_=resigner(meta,links,tmp_path)
    report,_=verify(meta,keys,links,tmp_path)
    assert report.records_for('package','materials')[0].rule_index==1
    traces=[t for t in report.rule_trace if t.item_name=='package' and t.source_type=='materials']
    assert [t.rule_index for t in traces]==[0,1,2]
    assert [t.consumed for t in traces]==[(),('stage/tool',),()]

def test_invalid_layout_signature_cannot_invoke_runner(tmp_path):
    meta,keys,links=generate(tmp_path);meta.signatures[0]['sig']='00'*64;calls=[]
    def runner(*a,**k):calls.append(True);raise AssertionError('must not run')
    with pytest.raises(Exception):in_toto_verify_coverage(meta,keys,link_dir_path=str(tmp_path),persist_inspection_links=False,inspection_runner=runner)
    assert calls==[]

def test_invalid_candidate_does_not_supply_evidence(tmp_path):
    meta,keys,links=generate(tmp_path)
    import json
    files=list(tmp_path.glob('compile.*.link'));assert len(files)==1
    raw=json.loads(files[0].read_text());raw['signed']['products']['evil/file']=HASH
    files[0].write_text(json.dumps(raw))
    calls=[]
    def runner(*a,**k):calls.append(True);raise AssertionError('must not run')
    with pytest.raises(Exception):in_toto_verify_coverage(meta,keys,link_dir_path=str(tmp_path),persist_inspection_links=False,inspection_runner=runner)
    assert calls==[]

def test_original_return_still_link(tmp_path):
    meta,keys,links=generate(tmp_path)
    result,calls=verify(meta,keys,links,tmp_path,old=True)
    assert isinstance(result,Link) and result.products=={'release/tool':HASH} and calls==['audit']

@pytest.mark.parametrize('rule,side,path,in_materials,in_products',[
    ('CREATE','products','created',False,True),('DELETE','materials','deleted',True,False),
    ('MODIFY','materials','changed',True,True),('MODIFY','products','changed',True,True)])
def test_two_sided_create_delete_modify_proof(rule,side,path,in_materials,in_products):
    link=Link(name='step',materials={'deleted':dict(HASH),'changed':dict(HASH)},products={'created':dict(HASH),'changed':{'sha256':'44'*32,'sha512':'55'*64}})
    collector=CoverageCollector(strict=False)
    verify_item_rules_coverage('step',side,[[rule,path]],{'step':link},collector,'step')
    row=collector.records[0]
    assert row.artifact==path and row.in_materials is in_materials and row.in_products is in_products
    assert bool(row.material_hashes) is in_materials and bool(row.product_hashes) is in_products
    assert row.binding==('hash-difference' if rule=='MODIFY' else 'set-membership')
