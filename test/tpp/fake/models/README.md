# README

These files are all generated:

```sh
wget https://venafi-tpp.platform-ops.jetstack.net/vedsdk/docs/swagger.yaml
swagger generate model \
    --model AuthorizeOAuthRequest \
    --model AuthorizeOAuthResponse \
    --model CSRData \
    --model CSRDetails \
    --model CheckPolicyRequest \
    --model CheckPolicyResponse \
    --model CompliantBoolValue \
    --model CompliantIntValue \
    --model CompliantListValues \
    --model CompliantValue \
    --model IdentityEntry \
    --model IdentityWebRequest \
    --model IdentityWebResponse \
    --model KeyPairData \
    --model LockedIntValue \
    --model LockedListValues \
    --model LockedValue \
    --model PolicyData \
    --model SubjectData \
    --model-package test/tpp/fake/models
```
