import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import MainScreen from './src/screens/MainScreen';
import ResultScreen from './src/screens/ResultScreen';
import DetailScreen from './src/screens/DetailScreen';

const Stack = createNativeStackNavigator();

export default function App() {
  return (
    <NavigationContainer>
      <Stack.Navigator initialRouteName="Main">
        <Stack.Screen name="Main" component={MainScreen} options={{ title: 'AntiScam' }} />
        <Stack.Screen name="Result" component={ResultScreen} options={{ title: 'Kết quả' }} />
        <Stack.Screen name="Detail" component={DetailScreen} options={{ title: 'Chi tiết' }} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
