import React, { useState } from 'react';
import { View, TextInput, Button, Text, FlatList } from 'react-native';

export default function MainScreen({ navigation }) {
  const [url, setUrl] = useState('');

  const handleScan = () => {
    navigation.navigate('Result', { url });
  };

  return (
    <View style={{ padding: 16 }}>
      <TextInput
        placeholder="Nhập URL cần kiểm tra..."
        value={url}
        onChangeText={setUrl}
        autoCapitalize="none"
        autoCorrect={false}
        style={{ borderWidth: 1, padding: 12, marginBottom: 12 }}
      />
      <Button title="Kiểm tra" onPress={handleScan} />
    </View>
  );
}
