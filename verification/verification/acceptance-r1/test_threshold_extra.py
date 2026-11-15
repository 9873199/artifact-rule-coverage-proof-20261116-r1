import pytest
from securesystemslib.signer import CryptoSigner
from in_toto.models.metadata import Metablock
from in_toto.models.link import Link,FILENAME_FORMAT
from in_toto.exceptions import ThresholdVerificationError
from signed_fixtures import generate,HASH
from test_contract import verify

def second_candidate(meta,links,directory,*,threshold,invalid):
    signer=CryptoSigner.generate_ed25519();kid=signer.public_key.keyid
    pub=signer.public_key.to_dict();pub['keyid']=kid
    meta.signed.keys[kid]=pub;meta.signed.steps[0].pubkeys.append(kid);meta.signed.steps[0].threshold=threshold
    second=Link(name='compile',materials={'src/code':dict(HASH)},products={'evil/file':dict(HASH)},command=[])
    candidate=Metablock(signed=second);candidate.create_signature(signer)
    if invalid:candidate.signatures[0]['sig']='00'*64
    candidate.dump(str(directory/FILENAME_FORMAT.format(step_name='compile',keyid=kid)))
    owner=CryptoSigner.generate_ed25519();meta.signatures=[];meta.create_signature(owner)
    public=owner.public_key.to_dict();public['keyid']=owner.public_key.keyid
    return {owner.public_key.keyid:public},kid

def test_rejected_signed_candidate_cannot_fill_proof(tmp_path):
    meta,keys,links=generate(tmp_path)
    keys,kid=second_candidate(meta,links,tmp_path,threshold=1,invalid=True)
    report,calls=verify(meta,keys,links,tmp_path)
    assert report.ok and calls==['audit']
    assert all(r.artifact!='evil/file' for r in report.records)
    adopted=next(r for r in report.verified_links if r.item_name=='compile')
    assert kid not in adopted.keyids and len(adopted.keyids)==1

def test_threshold_two_disagreement_fails_without_inspection(tmp_path):
    meta,keys,links=generate(tmp_path)
    keys,kid=second_candidate(meta,links,tmp_path,threshold=2,invalid=False)
    with pytest.raises(ThresholdVerificationError):verify(meta,keys,links,tmp_path)
