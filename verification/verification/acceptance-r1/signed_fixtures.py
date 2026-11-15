"""Generate real signed miniature layouts/links; no inspection subprocess runs."""
from pathlib import Path
from in_toto.models.layout import Layout,Step,Inspection
from in_toto.models.link import Link,FILENAME_FORMAT
from in_toto.models.metadata import Metablock
from securesystemslib.signer import CryptoSigner

HASH={'sha256':'11'*32,'sha512':'22'*64}


def generate(directory,*,uncovered=False,mismatch=False,threshold=1):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    owner=CryptoSigner.generate_ed25519();worker=CryptoSigner.generate_ed25519()
    kid=worker.public_key.keyid
    pub=worker.public_key.to_dict();pub['keyid']=kid
    owner_pub=owner.public_key.to_dict();owner_pub['keyid']=owner.public_key.keyid
    compile_step=Step(name='compile',pubkeys=[kid],threshold=threshold,
        expected_materials=[['ALLOW','src/code']],
        expected_products=[['ALLOW','build/tool']])
    package=Step(name='package',pubkeys=[kid],threshold=1,
        expected_materials=[['MATCH','*','IN','stage','WITH','PRODUCTS','IN','build','FROM','compile']],
        expected_products=[['ALLOW','release/tool']])
    inspection=Inspection(name='audit',run=['DO-NOT-EXECUTE'],
        expected_materials=[['MATCH','*','IN','release','WITH','PRODUCTS','IN','release','FROM','package']],
        expected_products=[])
    layout=Layout(steps=[compile_step,package],inspect=[inspection],keys={kid:pub},
        expires='2050-01-01T00:00:00Z')
    products={'build/tool':dict(HASH)}
    if uncovered:products['unexplained/file']=dict(HASH)
    stage_hash=dict(HASH)
    if mismatch:stage_hash['sha512']='33'*64
    links={
        'compile':Link(name='compile',materials={'src/code':dict(HASH)},products=products,command=[]),
        'package':Link(name='package',materials={'stage/tool':stage_hash},
            products={'release/tool':dict(HASH)},command=[]),
        'audit':Link(name='audit',materials={'release/tool':dict(HASH)},products={},byproducts={'return-value':0}),
    }
    for name in ('compile','package'):
        signed=Metablock(signed=links[name]);signed.create_signature(worker)
        signed.dump(str(directory/FILENAME_FORMAT.format(step_name=name,keyid=kid)))
    metadata=Metablock(signed=layout);metadata.create_signature(owner)
    # Private keys never leave this function or enter fixture files.
    return metadata,{owner.public_key.keyid:owner_pub},links


if __name__=='__main__':
    import sys
    from unittest.mock import patch
    from in_toto.verifylib import in_toto_verify
    metadata,keys,links=generate(sys.argv[1])
    calls=[]
    def runner(*args,**kwargs):calls.append(True);return {'audit':links['audit']}
    with patch('in_toto.verifylib.run_all_inspections',side_effect=runner):
        result=in_toto_verify(metadata,keys,link_dir_path=sys.argv[1],persist_inspection_links=False)
    assert calls==[True] and result.products=={'release/tool':HASH}
    print('Two signed steps and signed layout verified by original flow; injected inspection only; no subprocess.')
