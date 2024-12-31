import { createStore, applyMiddleware } from 'redux';
import { thunk } from 'redux-thunk';  // Import redux-thunk

// Initial state
const initialState = {
  step: 1,
  key: null,
  seedPhrase: null,
  password: '',
  wallet: null,
  encryptedSeed: null,
  passwordStep: false,  // This will control the password prompt step
  seedGenerationStep: false, // This will control the seed generation flow
  confirmationWord: '',
  selectedWord: '',
  confirmed: false,
};

// Action creators
export const setSeedGenerationStep = (step) => ({
  type: SET_SEED_GENERATION_STEP,
  payload: step,
});
// Action types
const SET_SEED_GENERATION_STEP = 'SET_SEED_GENERATION_STEP';  // New action type
const GENERATE_KEY = 'GENERATE_KEY';
const SET_STEP = 'SET_STEP';
const SET_SEED_PHRASE = 'SET_SEED_PHRASE';
const SET_PASSWORD = 'SET_PASSWORD';
const SET_WALLET = 'SET_WALLET';
const SET_ENCRYPTED_SEED = 'SET_ENCRYPTED_SEED';
const SET_CONFIRMATION_WORD = 'SET_CONFIRMATION_WORD';
const SET_SELECTED_WORD = 'SET_SELECTED_WORD';
const SET_CONFIRMED = 'SET_CONFIRMED';
const SET_ADDRESS = 'SET_ADDRESS'
const SET_ENCRYPTED_KEY = "SET_ENCRYPTED_KEY"
const SET_DECODED_TX = "SET_DECODED_TX"
const SET_TXID = "SET_TXID"

const handleNextStep = () => {
  const currentStep = useSelector(state => state.step);
  const nextStep = currentStep + 1;
  dispatch(setStep(nextStep));
};

// Action creators
export const generateKeyAction = () => ({ type: GENERATE_KEY });
export const setStep = (step) => ({ type: SET_STEP, payload: step });
export const setSeedPhrase = (seedPhrase) => ({ type: SET_SEED_PHRASE, payload: seedPhrase });
export const setPassword = (password) => ({ type: SET_PASSWORD, payload: password });
export const setWallet = (wallet) => ({ type: SET_WALLET, payload: wallet });
export const setEncryptedSeed = (encryptedSeed) => ({ type: SET_ENCRYPTED_SEED, payload: encryptedSeed });
export const setConfirmationWord = (confirmationWord) => ({ type: SET_CONFIRMATION_WORD, payload: confirmationWord });
export const setSelectedWord = (selectedWord) => ({ type: SET_SELECTED_WORD, payload: selectedWord });
export const setConfirmed = (confirmed) => ({ type: SET_CONFIRMED, payload: confirmed });
export const setAddress = (address) => ({type:SET_ADDRESS, payload: address})
export const setEncryptedKey = (encryptedKey) => ({type:SET_ENCRYPTED_KEY, payload: encryptedKey})
export const setDecodedTransaction = (decode) => ({type:SET_DECODED_TX, payload: decode})
export const setTxid = (txid) => ({ type: SET_TXID, payload: txid });
export const setMessageToSign = (message) => ({type: 'SET_MESSAGE', payload: message})
export const setTxToSign = (tx) => ({type: 'SET_TX_TOSIGN', payload: tx})
export const setSignRequest = (flag) => ({type: 'SET_SIGNREQUEST', payload: flag})
export const setConfirmationPasswordValue = (password) =>({type: 'SET_CONFIRMATIONPASSWORD', payload:password})
export const setPubKey = (pubKey) =>({type: 'SET_PUBKEY', payload:pubKey})
export const setPSBTToSign = (psbtHex, redeemKey) => ({
  type: 'SET_PSBT',
  payload: { psbtHex, redeemKey },
});
export const setRequestId = (id) => ({
  type: 'SET_REQUESTID',
  payload: id
})
export const setSelectedNetwork = (network) => ({type: 'SET_NETWORK', payload:network})
// Reducer to manage wallet creation steps and other states
const rootReducer = (state = initialState, action) => {
  switch (action.type) {
    case GENERATE_KEY:
      return { ...state, key: Math.random().toString(36).substring(2) };
    case SET_STEP:
      return { ...state, step: action.payload };
    case SET_SEED_PHRASE:
      return { ...state, seedPhrase: action.payload };
    case SET_SEED_GENERATION_STEP:
      return { ...state, seedGenerationStep: action.payload };
    case SET_PASSWORD:
      return { ...state, password: action.payload };
    case 'SET_CONFIRMATIONPASSWORD':
      return { ...state, password: action.payload };
    case SET_WALLET:
      return { ...state, wallet: action.payload };
    case SET_ENCRYPTED_SEED:
      return { ...state, encryptedSeed: action.payload };
    case SET_CONFIRMATION_WORD:
      return { ...state, confirmationWord: action.payload };
    case SET_SELECTED_WORD:
      return { ...state, selectedWord: action.payload };
    case SET_CONFIRMED:
      return { ...state, confirmed: action.payload };
    case SET_ADDRESS:
      return {...state, address: action.payload}
    case SET_ENCRYPTED_KEY:
      return {...state, encryptedKey: action.payload} 
    case SET_DECODED_TX:
      return {...state, decode: action.payload}   
    case SET_TXID:
      return {...state, txid: action.payload}
    case 'SET_MESSAGE':
      return {...state, message: action.payload}
    case 'SET_TX_TOSIGN':
      return {...state, tx: action.payload}
    case 'SET_SIGNREQUEST':
      return {...state, signRequest: action.payload}
    case 'SET_PUBKEY':
      return {...state, pubkey: action.payload} 
    case 'SET_PSBT':
      return { ...state, psbt: action.payload };
    case 'SET_REQUESTID':
      return { ...state, id: action.payload} 
    case 'SET_NETWORK':
      return {...state, network: action.payload}
    default:
      return state;
  }
};

// Create the store
const store = createStore(rootReducer, applyMiddleware(thunk));

export default store;
