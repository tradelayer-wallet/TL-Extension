

const NetworkSelector = ({ onNetworkChange }) => {
  const [selectedNetwork, setSelectedNetwork] = useState(networks[0]);
  const networks = [
  { name: 'Bitcoin Mainnet', network: bitcoin.networks.bitcoin, path: "m/44'/0'/0'/0/0" },
  { name: 'Bitcoin Testnet', network: bitcoin.networks.testnet, path: "m/44'/1'/0'/0/0" },
  { name: 'Litecoin Mainnet', network: litecoinNetwork, path: "m/44'/2'/0'/0/0" },
  { name: 'Litecoin Testnet', network: litecoinTestnet, path: "m/44'/1'/0'/0/0" },
  { name: 'Dogecoin Mainnet', network: dogecoinNetwork, path: "m/44'/3'/0'/0/0" }, // Assuming you define `dogecoinNetwork`
  { name: 'Dogecoin Testnet', network: dogecoinTestnet, path: "m/44'/1'/0'/0/0" }, // Assuming you define `dogecoinTestnet`
];


  const handleChange = (event) => {
    const network = networks.find(n => n.name === event.target.value);
    setSelectedNetwork(network);
    onNetworkChange(network);
  };

  return (
    <div className="network-selector">
      <label>Select Network:</label>
      <select value={selectedNetwork.name} onChange={handleChange}>
        {networks.map(network => (
          <option key={network.name} value={network.name}>
            {network.name}
          </option>
        ))}
      </select>
    </div>
  );
};
