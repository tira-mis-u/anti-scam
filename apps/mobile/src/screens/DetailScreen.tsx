import React from 'react';
import { View, Text } from 'react-native';

export default function DetailScreen({ route }) {
  const { url } = route.params;
  return (
    <View style={{ padding: 16 }}>
      <Text>Chi tiết phân tích cho: {url}</Text>
    </View>
  );
}
