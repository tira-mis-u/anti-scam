import React from 'react';
import { View, Text, Button } from 'react-native';

export default function ResultScreen({ route, navigation }) {
  const { url } = route.params;

  return (
    <View style={{ padding: 16 }}>
      <Text>URL: {url}</Text>
      <Text>Risk Score: —</Text>
      <Text>Signals: —</Text>
      <Button title="Chi tiết" onPress={() => navigation.navigate('Detail', { url })} />
    </View>
  );
}
