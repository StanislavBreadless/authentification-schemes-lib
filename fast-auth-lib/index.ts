export interface I2StepAuthVerifier<VMSG, PMSG> {
    getVerifierRequest(): VMSG;
    verify(proverResponse: PMSG): boolean;
}

export interface I2StepAuthProver<VMSG, PMSG> {
    getProverMessage(verifierRequest: VMSG): PMSG;
}

export interface I3StepAuthVerifier<PMSG1, VMSG, PMSG2> {
    getVerifierRequest(proverRequest: PMSG1): VMSG;
    verify(proverResponse: PMSG2): boolean;
}

export interface I3StepAuthProver<PMSG1, VMSG, PMSG2> {
    getFirstProverMessage(): PMSG1;
    getProverSecondMessage(verifierRequest: VMSG): PMSG2;
}

export interface I2StepProtocolDescriptor<VMSG, PMSG, VINIT, PINIT> {
    newVerifier(verifierParams: VINIT): I2StepAuthVerifier<VMSG, PMSG>;
    newProver(proverParams: PINIT): I2StepAuthProver<VMSG, PMSG>;
}

export interface I3StepProtocolDescriptor<PMSG1, VMSG, PMSG2, VINIT, PINIT> {
    newVerifier(verifierParams: VINIT): I3StepAuthVerifier<PMSG1, VMSG, PMSG2>;
    newProver(proverParams: PINIT): I3StepAuthProver<PMSG1, VMSG, PMSG2>;
}

export { SchnorrProtocol } from './schnorr';
export { FA3FSProtocol } from './fa3fs';
